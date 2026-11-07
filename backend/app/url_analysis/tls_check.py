"""TLS certificate and trust analysis (Module 2).

A valid certificate only means the connection is encrypted to whoever controls the
domain. It is never treated as evidence that the site is safe.
"""

import socket
import ssl
import warnings
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..cache import TTLCache, cache_completed_checks
from ..schemas import Severity
from .common import CheckResult, indicator
from .distrusted_cas import find_distrusted
from .safe_fetch import BlockedDestination, DnsFailure, resolve_public_ips

SOURCE = "Vexora TLS analysis"
TIMEOUT_SECONDS = 6
# Certificates rarely change, but can be replaced at any time, so keep this short.
TLS_CACHE = TTLCache("tls", 3600)

VERIFY_PROBLEMS = {
    10: ("Certificate has expired", "The certificate is past its expiry date."),
    18: ("Self-signed certificate", "The certificate was not issued by a trusted certificate authority."),
    19: ("Self-signed certificate in the chain", "The chain ends in a certificate no browser trusts."),
    20: ("Untrusted or incomplete certificate chain", "The issuer could not be linked to a trusted root."),
    21: ("Untrusted or incomplete certificate chain", "The issuer could not be linked to a trusted root."),
    23: ("Certificate has been revoked", "The certificate authority has cancelled this certificate."),
    62: ("Certificate does not match the domain", "The certificate was issued for a different name."),
}


@cache_completed_checks(TLS_CACHE, key=lambda host, prefix="": (host.lower(), prefix))
def check_tls(host: str, prefix: str = "") -> CheckResult:
    result = CheckResult(name=f"{prefix}TLS certificate", completed=False)

    def add(title: str, severity: Severity, evidence: str) -> None:
        result.indicators.append(indicator(prefix + title, severity, evidence, SOURCE))

    try:
        ip = resolve_public_ips(host)[0]
    except (BlockedDestination, DnsFailure) as error:
        result.limitations.append(f"TLS not checked: {error}.")
        return result

    verified, verify_code, verify_message, tls_version = _verify(host, ip)
    if verified is None:
        add(
            "HTTPS is not available",
            Severity.LOW,
            f"Could not open an HTTPS connection to {host} on port 443 ({verify_message}).",
        )
        result.completed = True
        result.details = {"https_available": False}
        return result

    try:
        leaf, chain, unverified_version = _retry(lambda: _fetch_certificates(host, ip))
    except (OSError, ValueError) as error:
        result.limitations.append(f"Could not read the certificate from {host} ({error}).")
        return result

    result.completed = True
    details = _describe(leaf, host)
    details["tls_version"] = tls_version or unverified_version
    details["trusted_by_this_server"] = bool(verified)
    details["chain_length"] = len(chain)
    result.details = details

    if verified:
        add(
            "Certificate is valid and trusted",
            Severity.INFO,
            f"Issued to {', '.join(details['names'][:3]) or host} by {details['issuer']}, valid until "
            f"{details['valid_until'][:10]}. A valid certificate does not mean the site is legitimate.",
        )
    else:
        # Prefer facts from the certificate itself over the first error OpenSSL happened to report.
        if details["days_until_expiry"] < 0:
            verify_code = 10
        elif details["subject"] == details["issuer"] and verify_code in (20, 21):
            verify_code = 18
        elif not details["matches_host"] and verify_code in (20, 21):
            verify_code = 62
        title, explanation = VERIFY_PROBLEMS.get(verify_code, ("Certificate verification failed", ""))
        add(
            title,
            Severity.HIGH,
            f"{explanation} Verification error: {verify_message.rstrip('.')}. Issuer: {details['issuer']}.".strip(),
        )

    issuers = [details["issuer"], details["issuer_org"]] + [_name(cert.issuer) for cert in chain[1:]]
    distrusted = find_distrusted(issuers, leaf.not_valid_before_utc.date())
    if distrusted:
        add(
            f"Issued by a distrusted certificate authority ({distrusted.name})",
            Severity.HIGH,
            f"Trust incident, not a configuration error: {distrusted.reason} Source: {distrusted.source}.",
        )

    days_left = details["days_until_expiry"]
    if verified and 0 <= days_left <= 7:
        add("Certificate expires very soon", Severity.LOW, f"It expires in {days_left} days.")
    if verified and not details["matches_host"]:
        add("Certificate names do not include this host", Severity.MEDIUM, f"Names: {', '.join(details['names'][:5])}.")

    key_type, key_bits = details["key_type"], details["key_bits"]
    if (key_type in ("RSA", "DSA") and key_bits < 2048) or (key_type == "EC" and key_bits < 256):
        add("Weak public key", Severity.MEDIUM, f"{key_type} key of {key_bits} bits is below current minimums.")
    if details["signature_hash"] in ("sha1", "md5"):
        add("Weak signature algorithm", Severity.MEDIUM, f"The certificate is signed with {details['signature_hash'].upper()}.")
    if details["validity_days"] > 398:
        add(
            "Unusually long certificate lifetime",
            Severity.LOW,
            f"Valid for {details['validity_days']} days. Publicly trusted certificates are limited to 398 days.",
        )
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        add("Outdated TLS version", Severity.MEDIUM, f"The server negotiated {tls_version}.")

    result.limitations.append("Certificate revocation (OCSP/CRL) is not checked.")
    return result


def _retry(action):
    """Try once more if the connection is dropped, which happens on flaky networks."""
    try:
        return action()
    except (ConnectionResetError, TimeoutError):
        return action()


def _verify(host: str, ip: str) -> tuple[bool | None, int | None, str, str | None]:
    """Returns (verified, error code, message, TLS version). verified is None if HTTPS is unreachable."""
    try:
        return _retry(lambda: _verify_once(host, ip))
    except OSError as error:
        return None, None, type(error).__name__, None


def _verify_once(host: str, ip: str) -> tuple[bool | None, int | None, str, str | None]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return True, None, "", tls.version()
    except ssl.SSLCertVerificationError as error:
        return False, error.verify_code, error.verify_message or str(error), None
    except ssl.SSLError as error:
        return None, None, f"TLS handshake failed: {error.reason or error}", None


def _fetch_certificates(host: str, ip: str) -> tuple[x509.Certificate, list[x509.Certificate], str | None]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, 443), timeout=TIMEOUT_SECONDS) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            raw_chain = tls.get_unverified_chain() if hasattr(tls, "get_unverified_chain") else None
            version = tls.version()
    if not der:
        raise ValueError("the server sent no certificate")
    leaf = x509.load_der_x509_certificate(der)
    chain = [_load(item) for item in (raw_chain or [])] or [leaf]
    return leaf, [cert for cert in chain if cert is not None], version


def _load(item) -> x509.Certificate | None:
    try:
        with warnings.catch_warnings():
            # Some servers send certificates that break RFC 5280 rules; read them anyway.
            warnings.simplefilter("ignore")
            return _load_unchecked(item)
    except Exception:
        return None


def _load_unchecked(item) -> x509.Certificate:
    if isinstance(item, bytes):
        return x509.load_der_x509_certificate(item)
    return x509.load_der_x509_certificate(item.public_bytes(ssl._ssl.ENCODING_DER))


def _describe(cert: x509.Certificate, host: str) -> dict:
    now = datetime.now(timezone.utc)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", key.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", key.key_size
    else:
        key_type, key_bits = type(key).__name__.replace("PublicKey", ""), 256

    try:
        signature_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        signature_hash = None

    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "issuer_org": _attribute(cert.issuer, NameOID.ORGANIZATION_NAME),
        "names": names,
        "matches_host": any(_name_matches(name, host) for name in names),
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_until": cert.not_valid_after_utc.isoformat(),
        "days_until_expiry": (cert.not_valid_after_utc - now).days,
        "validity_days": (cert.not_valid_after_utc - cert.not_valid_before_utc).days,
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_hash": signature_hash,
        "serial_number": format(cert.serial_number, "x"),
    }


def _name(name: x509.Name) -> str:
    return (
        _attribute(name, NameOID.COMMON_NAME)
        or _attribute(name, NameOID.ORGANIZATION_NAME)
        or name.rfc4514_string()
    )


def _attribute(name: x509.Name, oid) -> str:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else ""


def _name_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host.count(".") == pattern.count(".")
    return pattern == host
