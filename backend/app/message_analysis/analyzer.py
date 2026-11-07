"""Analyses a pasted message: fixed rules, extracted details, and every link
checked with the URL analysis. The AI layer (app/ai.py) only explains the result."""

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ..schemas import Classification, Indicator, Report, Severity
from ..url_analysis.analyzer import analyze_url_cached as analyze_url
from ..url_analysis.classify import classify, sort_indicators
from ..url_analysis.common import indicator
from ..url_analysis.domain_checks import BRANDS
from ..url_analysis.normalize import InvalidUrl, normalize_url
from .extract import extract
from .rules import SOURCE as LANGUAGE_SOURCE
from .rules import apply_rules

MAX_LINKS = 3

MESSAGE_ACTIONS = {
    Classification.CONFIRMED_MALICIOUS: [
        "Do not open the links, call the numbers or reply to this message.",
        "If you already shared an OTP, password or payment, contact your bank immediately and change your passwords.",
        "Report it at cybercrime.gov.in or call the 1930 cybercrime helpline (India), then delete it.",
    ],
    Classification.HIGH_RISK: [
        "Do not reply, open the links, call the numbers or make any payment.",
        "Never share an OTP, PIN or password. Contact the organisation through its official app or website.",
        "Report the message at cybercrime.gov.in or on the 1930 helpline (India), or to sancharsaathi.gov.in (Chakshu).",
    ],
    Classification.SUSPICIOUS: [
        "Check the claim independently: contact the organisation using details from its official website or app.",
        "Do not share OTPs, passwords or payment details in reply to this message.",
    ],
    Classification.INCONCLUSIVE: [
        "Not enough evidence could be collected. Do not treat this message as genuine just because of this result.",
    ],
    Classification.LOW_RISK: [
        "No significant warning signs were found, but this does not prove the message is genuine.",
        "Never share OTPs or passwords in reply to any message, however genuine it looks.",
    ],
}
SOURCE = "Vexora message analysis"

# How a message might name an organisation -> the brand key used in BRANDS.
BRAND_ALIASES = {
    r"\bsbi\b|state bank": "sbi",
    r"\bhdfc\b": "hdfcbank",
    r"\bicici\b": "icicibank",
    r"\baxis bank\b": "axisbank",
    r"\bkotak\b": "kotak",
    r"\bpaytm\b": "paytm",
    r"\bphonepe\b": "phonepe",
    r"\bamazon\b": "amazon",
    r"\bflipkart\b": "flipkart",
    r"\birctc\b": "irctc",
    r"income tax": "incometax",
    r"\buidai\b|\baadhaa?r\b": "uidai",
    r"india post": "indiapost",
    r"\bpaypal\b": "paypal",
    r"\bnetflix\b": "netflix",
    r"\bwhatsapp\b": "whatsapp",
    r"\bmicrosoft\b|\boutlook\b": "microsoft",
    r"\bapple\b|\bicloud\b": "apple",
    r"\bgoogle\b|\bgmail\b": "google",
    r"\bfedex\b": "fedex",
    r"\bdhl\b": "dhl",
}

LINK_SEVERITY = {
    Classification.CONFIRMED_MALICIOUS: Severity.CRITICAL,
    Classification.HIGH_RISK: Severity.HIGH,
    Classification.SUSPICIOUS: Severity.MEDIUM,
}


def analyze_message(message: str) -> Report:
    analysed_at = datetime.now(timezone.utc)
    indicators, matched_rules = apply_rules(message)
    extracted = extract(message)
    brands = [brand for pattern, brand in BRAND_ALIASES.items() if re.search(pattern, message, re.IGNORECASE)]
    limitations: list[str] = []

    urls = extracted.urls[:MAX_LINKS]
    if len(extracted.urls) > MAX_LINKS:
        limitations.append(f"Only the first {MAX_LINKS} of {len(extracted.urls)} links were checked.")
    with ThreadPoolExecutor(max_workers=MAX_LINKS) as pool:
        link_reports = list(pool.map(analyze_url, urls))

    confirmed = False
    links = []
    for url, report in zip(urls, link_reports):
        confirmed = confirmed or report.classification == Classification.CONFIRMED_MALICIOUS
        top = [item.title for item in report.indicators if item.severity not in (Severity.INFO, Severity.LOW)][:3]
        links.append({"url": url, "classification": report.classification.value, "top_findings": top})
        severity = LINK_SEVERITY.get(report.classification)
        if severity:
            indicators.append(
                indicator(
                    f"Link is {report.classification.value.lower()}: {_host(url)}",
                    severity,
                    "; ".join(top) or "See the link analysis.",
                    "Vexora URL analysis",
                )
            )
        other_warning = report.classification in LINK_SEVERITY or any(
            item.severity in (Severity.MEDIUM, Severity.HIGH) for item in indicators if item.source == "Vexora message rules"
        )
        indicators += _brand_mismatch(url, brands, other_warning)

    if extracted.upi_ids and "payment_request" in matched_rules:
        indicators.append(
            indicator(
                "Payment requested to a UPI ID",
                Severity.MEDIUM,
                f"The message asks for money and gives the UPI ID(s) {', '.join(extracted.upi_ids)}. "
                "UPI payments are instant and very hard to reverse.",
                LANGUAGE_SOURCE,
            )
        )

    indicators = sort_indicators(indicators)
    classification = classify(indicators, confirmed, site_reached=True, threat_intel_available=True)

    warnings = [item for item in indicators if item.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    technical = any(item.source != LANGUAGE_SOURCE for item in warnings)
    if confirmed:
        basis = "verified by threat intelligence"
    elif technical:
        basis = "technical and language checks"
    elif warnings:
        basis = "language patterns only"
        limitations.append(
            "This result is based on language patterns only. It shows the message looks like a scam, not verified proof of fraud."
        )
    else:
        basis = "no warning signs found"
    if not urls:
        limitations.append("The message contains no links, so no website was checked.")
    limitations += [
        "Phone numbers, UPI IDs and email addresses are extracted but not checked against a fraud database.",
        "Automated checks cannot prove that a message is genuine.",
    ]

    details = {
        "extracted": extracted.as_dict(),
        "organisations_mentioned": brands,
        "links": links,
        "rules_matched": matched_rules,
        "evidence_basis": basis,
    }
    coverage = (
        f"High (message rules and {len(urls)} link check(s) completed)"
        if urls
        else "Medium (message rules only; there were no links to check)"
    )
    return Report(
        input=message,
        classification=classification,
        indicators=indicators,
        confidence=coverage,
        recommended_actions=MESSAGE_ACTIONS[classification],
        limitations=list(dict.fromkeys(limitations)),
        analysed_at=analysed_at,
        details=details,
    )


def _brand_mismatch(url: str, brands: list[str], other_warning: bool) -> list[Indicator]:
    """One finding per link whose domain is not official for any brand the message names."""
    try:
        target = normalize_url(url)
    except InvalidUrl:
        return []
    named = [brand for brand in brands if BRANDS.get(brand)]
    if not named or any(target.registered_domain in BRANDS[brand] for brand in named):
        return []
    official = sorted({domain for brand in named for domain in BRANDS[brand][:2]})
    return [
        indicator(
            f"Mentions {', '.join(named)} but links to another site",
            # On its own this can be innocent (e.g. a shop that accepts Paytm), so it is
            # only High when the message shows another warning sign.
            Severity.HIGH if other_warning else Severity.MEDIUM,
            f"The message mentions {', '.join(named)}, but its link goes to {target.registered_domain}, "
            f"which is not an official domain ({', '.join(official)}).",
            SOURCE,
        )
    ]


def _host(url: str) -> str:
    try:
        return normalize_url(url).host
    except InvalidUrl:
        return url
