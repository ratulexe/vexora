"""Pulls links, contact details and payment details out of a message, and redacts
personal details before anything is sent to an external AI service."""

import re
from dataclasses import dataclass, field

import tldextract

from ..url_analysis.normalize import refang

_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'()]+", re.IGNORECASE)
BARE_DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?:/[^\s<>\"'()]*)?",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", re.IGNORECASE)
UPI_PATTERN = re.compile(r"\b[\w.-]{2,256}@[a-z]{2,20}\b(?!\.)", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?<![\d+])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)|\b1800[\s-]?\d{3}[\s-]?\d{3,4}\b")
AMOUNT_PATTERN = re.compile(r"(?:₹|\brs\.?|\binr)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:lakh|lakhs|crore|k))?", re.IGNORECASE)
WALLET_PATTERN = re.compile(r"\b0x[a-f0-9]{40}\b|\bbc1[a-z0-9]{25,60}\b", re.IGNORECASE)
PAN_PATTERN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
LONG_NUMBER_PATTERN = re.compile(r"\b\d(?:[\s-]?\d){5,}\b")

TRAILING_PUNCTUATION = ".,;:!?)]}'\""


@dataclass
class Extracted:
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)
    wallets: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {key: value for key, value in self.__dict__.items() if value}


def extract(message: str) -> Extracted:
    text = refang_text(message)
    found = Extracted()

    emails = _unique(EMAIL_PATTERN.findall(text))
    found.emails = emails
    without_emails = EMAIL_PATTERN.sub(" ", text)
    found.upi_ids = _unique(UPI_PATTERN.findall(without_emails))

    urls = [match.rstrip(TRAILING_PUNCTUATION) for match in URL_PATTERN.findall(without_emails)]
    without_urls = URL_PATTERN.sub(" ", without_emails)
    for candidate in BARE_DOMAIN_PATTERN.findall(without_urls):
        candidate = candidate.rstrip(TRAILING_PUNCTUATION)
        host = candidate.split("/")[0]
        if _extract(host).suffix and not host.replace(".", "").isdigit():
            urls.append(candidate)
    found.urls = _unique(urls)

    found.phones = _unique(re.sub(r"[\s-]", "", phone) for phone in PHONE_PATTERN.findall(text))
    found.amounts = _unique(AMOUNT_PATTERN.findall(text))
    found.wallets = _unique(WALLET_PATTERN.findall(text))
    return found


def refang_text(text: str) -> str:
    text = re.sub(r"\bhxxp", "http", text, flags=re.IGNORECASE)
    for defanged, plain in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("[:]", ":")):
        text = text.replace(defanged, plain)
    return text


def redact(message: str) -> str:
    """Replace personal details with placeholders. Links are reduced to their host name."""
    text = refang_text(message)
    text = URL_PATTERN.sub(lambda match: f"[LINK: {_host(match.group(0))}]", text)
    text = EMAIL_PATTERN.sub("[EMAIL]", text)
    text = UPI_PATTERN.sub("[UPI_ID]", text)
    text = WALLET_PATTERN.sub("[WALLET]", text)
    text = PHONE_PATTERN.sub("[PHONE]", text)
    text = PAN_PATTERN.sub("[PAN]", text)
    text = LONG_NUMBER_PATTERN.sub("[NUMBER]", text)
    return text


def _host(url: str) -> str:
    try:
        return refang(url).split("://", 1)[-1].split("/")[0].split("@")[-1].lower()
    except Exception:
        return "link"


def _unique(items) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
