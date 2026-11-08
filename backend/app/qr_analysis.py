"""QR code investigation. The image is decoded in the browser; only its text arrives here.

- Links go through the full link analysis.
- UPI payment codes (upi://pay?...) get payment-specific checks. The key fact for users:
  scanning a UPI QR code can only SEND money, never receive it, which is exactly what
  "scan to receive your refund/prize" scams exploit.
- Anything else is treated as a message.
"""

import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from .ai import add_ai_analysis
from .correlation import Features, correlate, message_features, upi_contact
from .message_analysis.analyzer import BRAND_ALIASES, MESSAGE_ACTIONS
from .message_analysis.analyzer import analyze_message as run_message_analysis
from .message_analysis.rules import apply_rules
from .report_cache import link_report
from .schemas import Classification, Report, Severity
from .url_analysis.classify import classify, sort_indicators
from .url_analysis.common import indicator

SOURCE = "Vexora QR analysis"
LINK_PATTERN = re.compile(r"^(https?://|www\.)\S+$|^[a-z0-9-]+(\.[a-z0-9-]+)+(/\S*)?$", re.IGNORECASE)
RECEIVE_WORDS = re.compile(
    r"\b(receive|refund|cash ?back|prize|reward|won|winner|lottery|claim|bonus|gift|kyc|verify|verification|"
    r"credit(ed)?|get ₹|get rs|get inr|unlock|release)\b",
    re.IGNORECASE,
)
AUTHORITY_WORDS = {
    r"\brbi\b|reserve bank": "the Reserve Bank of India",
    r"income tax": "the Income Tax Department",
    r"\bpolice\b|cyber ?cell|\bcbi\b": "the police",
    r"\bcustoms\b": "customs",
    r"customer care|support team|help ?desk": "customer support",
    r"\bbank\b": "a bank",
}

UPI_ACTIONS = {
    Classification.LOW_RISK: [
        "This is a standard UPI payment code. Pay only if you meant to pay this person or shop.",
        "Check the payee name your UPI app shows before entering your PIN.",
    ],
    Classification.SUSPICIOUS: [
        "Do not enter your UPI PIN unless you are sure who you are paying.",
        "Scanning a UPI QR code can only send money from your account. It can never receive money.",
    ],
    Classification.HIGH_RISK: [
        "Do not scan this code or enter your UPI PIN: it will send money, not receive it.",
        "Genuine refunds, prizes and KYC updates never ask you to scan a code or enter a PIN.",
        "Report it at cybercrime.gov.in or call the 1930 helpline (India).",
    ],
    Classification.CONFIRMED_MALICIOUS: [
        "Do not scan this code or enter your UPI PIN.",
        "If you already paid, call your bank and the 1930 helpline (India) immediately.",
    ],
    Classification.INCONCLUSIVE: [
        "This code could not be fully checked. Do not pay unless you know the payee.",
    ],
}


def content_type(content: str) -> str:
    text = content.strip()
    if text.lower().startswith("upi://"):
        return "upi"
    if text.upper().startswith("WIFI:"):
        return "wifi"
    if LINK_PATTERN.match(text):
        return "link"
    return "text"


def analyze_qr(content: str) -> Report:
    content = content.strip()
    kind = content_type(content)
    if kind == "wifi":
        return wifi_report(content)
    if kind == "link":
        report = link_report(content)
    elif kind == "upi":
        report = analyze_upi(content)
        payee = report.details.get("qr", {}).get("payee_address", "")
        features = Features(contacts={upi_contact(payee)} if payee else set(), brands=set(report.details["claimed"]))
        report = correlate("qr", content, features, report, UPI_ACTIONS)
        report = add_ai_analysis(report, message=content)
    else:
        report = run_message_analysis(content)
        report = correlate("message", content, message_features(content, report), report, MESSAGE_ACTIONS)
        report = add_ai_analysis(report, message=content)

    report.details["qr_content_type"] = kind
    report.limitations.insert(0, "The QR image was decoded in your browser; only its text content was checked.")
    return report


def wifi_report(content: str) -> Report:
    """Wi-Fi codes hold a network password, so nothing is analysed, stored or sent to the AI."""
    network = re.search(r"S:((?:\.|[^;])*)", content)
    name = network.group(1) if network else "unknown"
    return Report(
        input=f"Wi-Fi network: {name}",
        classification=Classification.LOW_RISK,
        indicators=[
            indicator(
                "Wi-Fi network details",
                Severity.INFO,
                f"This code connects your device to the Wi-Fi network '{name}'. It does not contain a link or payment.",
                SOURCE,
            )
        ],
        confidence="High (content identified)",
        recommended_actions=[
            "Only join Wi-Fi networks you trust; public networks can watch unencrypted traffic.",
            "This code contains a network password, so Vexora did not store or share its content.",
        ],
        limitations=["Wi-Fi codes are not analysed further, to keep the network password private."],
        analysed_at=datetime.now(timezone.utc),
        details={"qr_content_type": "wifi"},
    )


def analyze_upi(content: str) -> Report:
    query = parse_qs(urlsplit(content).query)
    field = lambda name: (query.get(name) or [""])[0].strip()  # noqa: E731
    payee, name, amount, note = field("pa"), field("pn"), field("am"), field("tn")
    found = []

    def add(title: str, severity: Severity, evidence: str, source: str = SOURCE) -> None:
        found.append(indicator(title, severity, evidence, source))

    add(
        "Scanning this code sends money",
        Severity.INFO,
        f"It pays {name or 'an unnamed payee'} ({payee or 'no UPI ID'}). UPI QR codes can only send money from "
        "your account; they can never be used to receive money.",
    )

    if not re.fullmatch(r"[\w.\-]{2,256}@[a-zA-Z]{2,64}", payee):
        add("Malformed or missing UPI ID", Severity.MEDIUM, f"The payee address '{payee}' is not a valid UPI ID.")

    described = f"{name} {note}"
    if match := RECEIVE_WORDS.search(described):
        add(
            "Claims you will receive money",
            Severity.HIGH,
            f'The code says "{match.group(0)}" ({_quote(name, note)}), but scanning a UPI code and entering your PIN '
            "always sends money. This is how QR refund and prize scams work.",
        )

    brands, generic = _claimed_identities(name)
    handle = payee.split("@")[0].lower()
    impersonated = [brand for brand in brands if not _handle_matches(handle, brand)]
    if impersonated:
        add(
            f"Payee name impersonates {', '.join(_display(brand) for brand in impersonated)}",
            Severity.HIGH,
            f"The payee is named '{name}', but the UPI ID {payee} does not belong to them. Anyone can choose any "
            "display name for a UPI ID.",
        )
    elif generic and not brands:
        add(
            f"Payee name claims to be {', '.join(generic)}",
            Severity.MEDIUM,
            f"The payee is named '{name}'. Real organisations use their own verified UPI IDs, not '{payee}'.",
        )
    claimed = brands + generic

    if amount:
        add("Amount is pre-filled", Severity.LOW, f"The code pre-fills ₹{amount}, which is common in payment scams.")

    if note:
        rule_findings, _ = apply_rules(note)
        found += [item for item in rule_findings if item.severity != Severity.LOW]

    indicators = sort_indicators(found)
    classification = classify(indicators, confirmed=False, site_reached=True, threat_intel_available=True)
    return Report(
        input=content,
        classification=classification,
        indicators=indicators,
        confidence="High (all payment checks completed)",
        recommended_actions=UPI_ACTIONS[classification],
        limitations=["UPI IDs are not checked against a fraud database; only earlier Vexora reports are compared."],
        analysed_at=datetime.now(timezone.utc),
        details={
            "qr": {"type": "UPI payment", "payee_address": payee, "payee_name": name, "amount": amount, "note": note},
            "claimed": [label for label in claimed],
            "rules_matched": [],
        },
    )


def _claimed_identities(name: str) -> tuple[list[str], list[str]]:
    """Named brands (e.g. 'sbi') and generic authorities (e.g. 'a bank') in a payee name."""
    brands = [brand for pattern, brand in BRAND_ALIASES.items() if re.search(pattern, name, re.IGNORECASE)]
    generic = [label for pattern, label in AUTHORITY_WORDS.items() if re.search(pattern, name, re.IGNORECASE)]
    return list(dict.fromkeys(brands)), list(dict.fromkeys(generic))


def _handle_matches(handle: str, brand: str) -> bool:
    """Whether the UPI handle itself carries the brand, e.g. 'sbi.care@sbi' for SBI."""
    return brand in re.sub(r"[^a-z]", "", handle)


def _display(brand: str) -> str:
    return brand.upper() if len(brand) <= 4 else brand.title()


def _quote(name: str, note: str) -> str:
    parts = [f"name: '{name}'" if name else "", f"note: '{note}'" if note else ""]
    return ", ".join(part for part in parts if part)
