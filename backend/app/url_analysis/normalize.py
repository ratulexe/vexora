"""Turns whatever the user pasted into one clean, comparable URL."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import idna
import tldextract

# Use the bundled public suffix list so the server never downloads it at startup.
# Private suffixes (github.io, vercel.app, ...) are on, because each site under them
# has a different owner.
# .bank.in and .fin.in are India's restricted domains for banks and financial firms (RBI, 2025).
# They are newer than the bundled list, so without them "hdfc.bank.in" would be read as "hdfc" on "bank.in".
_extract = tldextract.TLDExtract(
    suffix_list_urls=(), include_psl_private_domains=True, extra_suffixes=("bank.in", "fin.in")
)

_OBFUSCATED_IP = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}")


class InvalidUrl(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedUrl:
    original: str
    url: str  # Clean URL without credentials or fragment, with an ASCII host
    scheme: str
    host: str  # ASCII (punycode) host
    unicode_host: str
    port: int
    path: str
    query: str
    userinfo: str  # Anything before "@" in the host part
    registered_domain: str
    domain_label: str  # Registered domain without its suffix, e.g. "paypal"
    subdomain: str
    suffix: str
    is_ip: bool
    obfuscated_ip: bool


def refang(text: str) -> str:
    """Undo common link 'defanging', such as hxxp:// and example[.]com."""
    text = text.strip()
    text = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    for defanged, plain in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("[:]", ":")):
        text = text.replace(defanged, plain)
    return text


def normalize_url(raw: str) -> NormalizedUrl:
    text = refang(raw)
    if not text:
        raise InvalidUrl("The URL is empty.")
    if any(char.isspace() for char in text):
        raise InvalidUrl("The URL contains spaces.")

    if "://" not in text:
        text = ("https:" if text.startswith("//") else "https://") + text

    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidUrl(f"Only http and https links can be analysed, not '{scheme}'.")

    hostname = (parts.hostname or "").rstrip(".")
    if not hostname:
        raise InvalidUrl("The URL has no host name.")

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as error:
        raise InvalidUrl("The URL has an invalid port.") from error

    is_ip = _is_ip(hostname)
    obfuscated_ip = not is_ip and bool(_OBFUSCATED_IP.fullmatch(hostname))
    if is_ip or obfuscated_ip:
        ascii_host = unicode_host = hostname
    else:
        ascii_host, unicode_host = _to_ascii_and_unicode(hostname)

    extracted = _extract(ascii_host)
    if hasattr(type(extracted), "top_domain_under_public_suffix"):
        registered = extracted.top_domain_under_public_suffix
    else:  # tldextract older than 5.3
        registered = extracted.registered_domain
    if is_ip or obfuscated_ip or not registered:
        registered, label, subdomain, suffix = ascii_host, ascii_host, "", extracted.suffix
    else:
        label, subdomain, suffix = extracted.domain, extracted.subdomain, extracted.suffix

    netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    if port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    path = parts.path or "/"
    clean_url = urlunsplit((scheme, netloc, path, parts.query, ""))

    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""

    return NormalizedUrl(
        original=raw,
        url=clean_url,
        scheme=scheme,
        host=ascii_host,
        unicode_host=unicode_host,
        port=port,
        path=path,
        query=parts.query,
        userinfo=userinfo,
        registered_domain=registered,
        domain_label=label,
        subdomain=subdomain,
        suffix=suffix,
        is_ip=is_ip,
        obfuscated_ip=obfuscated_ip,
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _to_ascii_and_unicode(host: str) -> tuple[str, str]:
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        if not host.isascii():
            raise InvalidUrl("The host name is not a valid domain name.") from None
        # Allow technically invalid but common ASCII names, such as ones with underscores.
        ascii_host = host.lower()
    try:
        unicode_host = idna.decode(ascii_host)
    except idna.IDNAError:
        unicode_host = ascii_host
    return ascii_host, unicode_host
