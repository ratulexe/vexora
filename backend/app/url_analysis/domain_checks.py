"""Checks on the URL text itself. No network access, so they are fast and always run."""

import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit

from ..schemas import Indicator, Severity
from .common import CheckResult, indicator
from .normalize import InvalidUrl, NormalizedUrl, normalize_url

SOURCE = "Vexora domain analysis"

# Brand name -> its official registered domains. Extend this list for your demo.
BRANDS: dict[str, tuple[str, ...]] = {
    "google": ("google.com", "google.co.in", "googleapis.com", "gstatic.com", "googleusercontent.com"),
    "gmail": ("gmail.com", "google.com"),
    "youtube": ("youtube.com", "youtu.be"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com"),
    "outlook": ("outlook.com", "live.com", "office.com", "microsoft.com"),
    "office365": ("office.com", "microsoft.com", "microsoftonline.com"),
    "apple": ("apple.com",),
    "icloud": ("icloud.com", "apple.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"),
    "flipkart": ("flipkart.com",),
    "paypal": ("paypal.com", "paypal.me"),
    "paytm": ("paytm.com", "paytmbank.com"),
    "phonepe": ("phonepe.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com"),
    "onlinesbi": ("onlinesbi.sbi", "sbi.bank.in", "sbi.co.in"),
    "hdfcbank": ("hdfcbank.com", "hdfc.bank.in"),
    "icicibank": ("icicibank.com", "icici.bank.in"),
    "axisbank": ("axisbank.com", "axis.bank.in"),
    "kotak": ("kotak.com", "kotak.bank.in"),
    "irctc": ("irctc.co.in",),
    "incometax": ("incometax.gov.in", "incometaxindia.gov.in"),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "indiapost": ("indiapost.gov.in",),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "linkedin": ("linkedin.com",),
    "github": ("github.com",),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "yahoo": ("yahoo.com",),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "zerodha": ("zerodha.com",),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com",),
}
OFFICIAL_DOMAINS = {domain for domains in BRANDS.values() for domain in domains}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "shorturl.gg",
}

REDIRECT_PARAMS = {
    "url", "u", "r", "redirect", "redirect_url", "redirect_uri", "redirecturl", "next",
    "return", "returnurl", "return_url", "returnto", "goto", "dest", "destination",
    "continue", "target", "rurl", "link", "out",
}

# Words phishing sites glue onto a brand name, as in "paypallogin" or "sbikyc".
PHISHING_WORDS = (
    "login", "signin", "secure", "verify", "verification", "account", "update", "support",
    "kyc", "auth", "confirm", "reward", "refund", "bonus", "alert", "billing", "wallet",
    "help", "service", "online", "unlock", "recovery", "netbanking", "bank", "pay", "otp",
)

# Real words that are one letter away from a brand name, e.g. "finance" and "binance".
NOT_TYPOS = {"finance", "cloud"}

# Characters from other alphabets that look like Latin letters, plus common digit swaps.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u",
    "α": "a", "ο": "o", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "ρ": "p",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}


def check_domain(url: NormalizedUrl, prefix: str = "") -> CheckResult:
    found: list[Indicator] = []

    def add(title: str, severity: Severity, evidence: str) -> None:
        found.append(indicator(prefix + title, severity, evidence, SOURCE))

    _check_structure(url, add)
    _check_lookalikes(url, add)
    _check_brands(url, add)
    _check_redirect_params(url, add)

    details = {
        "host": url.host,
        "unicode_host": url.unicode_host,
        "registered_domain": url.registered_domain,
        "subdomain": url.subdomain,
        "suffix": url.suffix,
    }
    return CheckResult(name="Domain analysis", completed=True, indicators=found, details=details)


def _check_structure(url: NormalizedUrl, add) -> None:
    if url.userinfo:
        add(
            "'@' trick hides the real destination",
            Severity.HIGH,
            f"Browsers ignore the text before '@' ('{url.userinfo}'). The link really goes to {url.host}.",
        )
    if url.obfuscated_ip:
        add(
            "Obfuscated IP address",
            Severity.HIGH,
            f"The host '{url.host}' is an IP address written in an unusual form to hide it.",
        )
    elif url.is_ip:
        add(
            "Raw IP address instead of a domain name",
            Severity.MEDIUM,
            f"The link points directly to {url.host}. Legitimate services almost always use a domain name.",
        )
    if url.registered_domain in SHORTENERS:
        add(
            "Link shortener hides the real destination",
            Severity.MEDIUM,
            f"{url.registered_domain} is a URL shortening service. The redirect analysis shows where it leads.",
        )
    if url.subdomain and url.subdomain.count(".") >= 3:
        add(
            "Unusually many subdomain levels",
            Severity.LOW,
            f"'{url.subdomain}' has {url.subdomain.count('.') + 1} levels, a pattern used to bury the real domain.",
        )
    readable_label = url.unicode_host.split(".")[-len(url.registered_domain.split("."))]
    if readable_label.count("-") >= 3:
        add(
            "Many hyphens in the domain name",
            Severity.LOW,
            f"'{readable_label}' has {readable_label.count('-')} hyphens.",
        )
    if len(url.url) > 150:
        add("Very long URL", Severity.LOW, f"The URL is {len(url.url)} characters long.")
    if url.port not in (80, 443):
        add("Non-standard port", Severity.LOW, f"The link uses port {url.port}.")
    if url.scheme == "http":
        add("Link does not use HTTPS", Severity.LOW, "The connection to this link is not encrypted.")


def _check_lookalikes(url: NormalizedUrl, add) -> None:
    if url.is_ip or "xn--" not in url.host:
        return
    mixed = [label for label in url.unicode_host.split(".") if len(_scripts(label)) > 1]
    if mixed:
        add(
            "Mixed alphabets in the domain name (homograph attack)",
            Severity.HIGH,
            f"'{url.unicode_host}' (encoded as {url.host}) mixes {', '.join(sorted(_scripts(mixed[0])))} "
            f"characters in '{mixed[0]}', so it can look identical to another domain.",
        )
    else:
        add(
            "Internationalised domain name",
            Severity.MEDIUM,
            f"'{url.unicode_host}' is encoded as {url.host}. Check that it is the site you expect.",
        )


def _check_brands(url: NormalizedUrl, add) -> None:
    if url.is_ip or url.obfuscated_ip or url.registered_domain in OFFICIAL_DOMAINS:
        return

    unicode_label = url.unicode_host.split(".")[-len(url.registered_domain.split("."))]
    label = _skeleton(unicode_label)
    label_tokens = _tokens(label)
    sub_tokens = _tokens(_skeleton(url.subdomain))
    path_tokens = _tokens(_skeleton(unquote(url.path)))

    for brand, official in BRANDS.items():
        official_text = ", ".join(official[:3])
        if brand in label_tokens or _brand_glued_to_phishing_word(brand, label):
            disguised = label != unicode_label.lower()
            add(
                f"Impersonates {brand} with look-alike characters" if disguised else f"Uses the name '{brand}' on an unofficial domain",
                Severity.HIGH,
                f"The site belongs to {url.registered_domain}, which is not an official {brand} domain "
                f"(official: {official_text}).",
            )
        elif len(brand) >= 6 and (match := _near_miss(brand, label_tokens + [label])):
            add(
                f"Looks like a misspelling of '{brand}' (typosquatting)",
                Severity.HIGH,
                f"'{match}' in {url.registered_domain} is one or two characters away from '{brand}' "
                f"(official: {official_text}).",
            )
        elif brand in sub_tokens:
            add(
                f"'{brand}' used in the subdomain of an unrelated site",
                Severity.HIGH,
                f"'{brand}' appears in '{url.subdomain}', but the site actually belongs to {url.registered_domain}.",
            )
        elif len(brand) >= 5 and brand in path_tokens:
            add(
                f"'{brand}' appears in the link path",
                Severity.LOW,
                f"The path '{url.path[:80]}' mentions {brand}, but the site belongs to {url.registered_domain}.",
            )


def _check_redirect_params(url: NormalizedUrl, add) -> None:
    for key, value in parse_qsl(url.query, keep_blank_values=False):
        if key.lower() not in REDIRECT_PARAMS:
            continue
        target = unquote(value).strip()
        if target.startswith("//"):
            target = "https:" + target
        if not re.match(r"^https?://", target, re.IGNORECASE):
            continue
        try:
            target_url = normalize_url(target)
        except InvalidUrl:
            continue
        if target_url.registered_domain != url.registered_domain:
            add(
                "Embedded redirect to another domain",
                Severity.MEDIUM,
                f"The '{key}' parameter sends visitors on to {target_url.host} ({urlsplit(target).netloc}).",
            )


def _skeleton(text: str) -> str:
    return "".join(CONFUSABLES.get(char, char) for char in text.lower())


def _tokens(text: str) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", text) if token]


def _scripts(label: str) -> set[str]:
    return {unicodedata.name(char, "UNKNOWN").split(" ")[0] for char in label if char.isalpha()}


def _brand_glued_to_phishing_word(brand: str, label: str) -> bool:
    """True for labels like "paypallogin" or "securehdfcbank", but not "applebees"."""
    if brand not in label or brand == label:
        return False
    rest = label.replace(brand, " ", 1)
    return any(word in rest for word in PHISHING_WORDS)


def _near_miss(brand: str, candidates: list[str]) -> str | None:
    limit = 1 if len(brand) < 9 else 2
    for candidate in candidates:
        if candidate in NOT_TYPOS or len(candidate) < 5:
            continue
        if candidate != brand and abs(len(candidate) - len(brand)) <= limit:
            if _edit_distance(candidate, brand) <= limit:
                return candidate
    return None


def _edit_distance(a: str, b: str) -> int:
    """Edits needed to turn a into b. Swapping two neighbouring letters counts as one."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]
