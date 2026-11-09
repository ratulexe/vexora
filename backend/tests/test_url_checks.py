"""Offline tests for the URL analysis checks. No test here touches the network."""

from datetime import date, datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.schemas import Classification, Indicator, Severity
from app.url_analysis.classify import classify
from app.url_analysis.distrusted_cas import find_distrusted
from app.url_analysis.domain_checks import check_domain
from app.url_analysis.normalize import InvalidUrl, normalize_url
from app.url_analysis.safe_fetch import BlockedDestination, check_destination, is_public_address, resolve_public_ips
from app.url_analysis import safe_fetch
from app.url_analysis.tls_check import _describe, _name_matches


def titles(url: str) -> list[str]:
    return [item.title for item in check_domain(normalize_url(url)).indicators]


# Normalisation


def test_adds_scheme_and_lowercases_host():
    url = normalize_url("WWW.Example.COM/Path")
    assert url.url == "https://www.example.com/Path"
    assert url.registered_domain == "example.com"


def test_refangs_defanged_links():
    assert normalize_url("hxxps://evil[.]example[.]com/x").host == "evil.example.com"


def test_converts_unicode_host_to_punycode():
    url = normalize_url("https://аpple.com")
    assert url.host == "xn--pple-43d.com"
    assert url.unicode_host == "аpple.com"


def test_strips_credentials_from_clean_url():
    url = normalize_url("https://google.com@evil.example.org/login")
    assert url.host == "evil.example.org"
    assert url.userinfo == "google.com"
    assert "@" not in url.url


@pytest.mark.parametrize("raw", ["", "javascript:alert(1)", "ftp://example.com", "https://exa mple.com"])
def test_rejects_invalid_input(raw):
    with pytest.raises(InvalidUrl):
        normalize_url(raw)


# Domain checks: suspicious


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://paypa1-secure-login.com", "Impersonates paypal with look-alike characters"),
        ("https://hdfcbank-kyc-update.in", "Uses the name 'hdfcbank' on an unofficial domain"),
        ("https://secure-paypallogin.com", "Uses the name 'paypal' on an unofficial domain"),
        ("https://www.paypal.com.account-update.info", "'paypal' used in the subdomain of an unrelated site"),
        ("https://flipkrat.com", "Looks like a misspelling of 'flipkart' (typosquatting)"),
        ("https://gogle.com", "Looks like a misspelling of 'google' (typosquatting)"),
        ("https://аpple.com", "Mixed alphabets in the domain name (homograph attack)"),
        ("https://google.com@203.0.113.7/", "'@' trick hides the real destination"),
        ("http://2130706433/", "Obfuscated IP address"),
        ("https://bit.ly/abc", "Link shortener hides the real destination"),
        ("https://example.com/r?url=https://evil.example.org/", "Embedded redirect to another domain"),
    ],
)
def test_flags_phishing_patterns(url, expected):
    assert expected in titles(url)


# Domain checks: benign look-alikes must not be flagged


@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com/signin",
        "https://www.onlinesbi.sbi",
        "https://accounts.google.com",
        "https://applebees.com",
        "https://finance.yahoo.com",
        "https://kodak.com",
        "https://my.cloud.com",
        "https://cloud.com",
        "https://amazonaws.com",
        "https://example.com/r?next=/dashboard",
    ],
)
def test_does_not_flag_legitimate_domains(url):
    assert titles(url) == []


# SSRF protection


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "::ffff:127.0.0.1", "100.64.0.1"]
)
def test_non_public_addresses_are_rejected(ip):
    assert not is_public_address(ip)


def test_public_address_is_allowed():
    assert is_public_address("8.8.8.8")


def test_nat64_addresses_are_judged_by_the_wrapped_ipv4_address():
    assert is_public_address("64:ff9b::808:808")  # 8.8.8.8
    assert not is_public_address("64:ff9b::7f00:1")  # 127.0.0.1
    assert not is_public_address("64:ff9b::a9fe:a9fe")  # 169.254.169.254


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "169.254.169.254", "::1"])
def test_resolving_internal_hosts_is_blocked(host):
    with pytest.raises(BlockedDestination):
        resolve_public_ips(host)


@pytest.mark.parametrize("url", ["ftp://example.com/", "https://example.com:8080/", "file:///etc/passwd"])
def test_disallowed_schemes_and_ports_are_blocked(url):
    with pytest.raises(BlockedDestination):
        check_destination(url)


# TLS certificate parsing


def make_certificate(names: list[str], days_valid: int, key_size: int = 2048) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )


def test_describes_certificate():
    details = _describe(make_certificate(["example.com", "*.example.com"], 90), "www.example.com")
    assert details["matches_host"] is True
    assert details["key_type"] == "RSA" and details["key_bits"] == 2048
    assert details["signature_hash"] == "sha256"
    assert 88 <= details["days_until_expiry"] <= 90


def test_wildcard_matches_only_one_level():
    assert _name_matches("*.example.com", "www.example.com")
    assert not _name_matches("*.example.com", "a.b.example.com")
    assert not _name_matches("*.example.com", "example.com")


def test_distrusted_ca_matching_respects_dates():
    assert find_distrusted(["DigiNotar Public CA"], date(2011, 1, 1)).name == "DigiNotar"
    entrust_chain = ["Entrust Certification Authority - L1K", "Entrust Root Certification Authority - G2"]
    assert find_distrusted(entrust_chain, date(2024, 1, 1)) is None
    assert find_distrusted(entrust_chain, date(2025, 1, 1)).name == "Entrust"
    assert find_distrusted(["Let's Encrypt R11"], date(2025, 1, 1)) is None


def test_entrust_certificates_under_sectigo_roots_are_trusted():
    # sbi.co.in (2026): Entrust-branded, but chained to Sectigo's root, which browsers trust.
    chain = ["Entrust DV TLS Issuing RSA CA 2", "Entrust Limited", "Sectigo Public Server Authentication Root R46"]
    assert find_distrusted(chain, date(2026, 6, 16)) is None


# Classification


def make(severity: Severity) -> Indicator:
    return Indicator(title=severity.value, severity=severity, evidence="", source="test")


def test_threat_intel_match_is_confirmed():
    assert classify([], confirmed=True, site_reached=False, threat_intel_available=True) == Classification.CONFIRMED_MALICIOUS


def test_two_high_indicators_are_high_risk():
    found = [make(Severity.HIGH), make(Severity.HIGH)]
    assert classify(found, False, True, True) == Classification.HIGH_RISK


def test_one_medium_indicator_is_suspicious():
    assert classify([make(Severity.MEDIUM)], False, True, True) == Classification.SUSPICIOUS


def test_low_and_info_indicators_do_not_raise_risk():
    found = [make(Severity.LOW), make(Severity.INFO)]
    assert classify(found, False, True, True) == Classification.LOW_RISK


def test_no_evidence_is_inconclusive_not_safe():
    assert classify([], False, site_reached=False, threat_intel_available=True) == Classification.INCONCLUSIVE
    assert classify([], False, site_reached=True, threat_intel_available=False) == Classification.INCONCLUSIVE


def _fake_addresses(*ips):
    return lambda host, port, type=0: [(None, None, None, "", (ip, 0)) for ip in ips]


def test_ipv4_addresses_come_before_ipv6(monkeypatch):
    # facebook.com publishes both; Render cannot reach IPv6, so IPv4 must be tried first.
    monkeypatch.setattr(
        safe_fetch.socket, "getaddrinfo", _fake_addresses("2a03:2880:f18a:188:face:b00c:0:25de", "57.144.94.1")
    )
    assert resolve_public_ips("facebook.com") == ["57.144.94.1", "2a03:2880:f18a:188:face:b00c:0:25de"]


def test_first_reachable_falls_back_to_the_next_address(monkeypatch):
    tried = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def connect(address, timeout):
        tried.append(address[0])
        if address[0] == "2001:db8::1":
            raise OSError("Network is unreachable")
        return Connection()

    monkeypatch.setattr(safe_fetch.socket, "create_connection", connect)
    assert safe_fetch.first_reachable(["2001:db8::1", "93.184.215.14"], 443) == "93.184.215.14"
    assert tried == ["2001:db8::1", "93.184.215.14"]


def test_first_reachable_skips_the_probe_for_a_single_address(monkeypatch):
    def connect(address, timeout):
        raise AssertionError("should not probe a single address")

    monkeypatch.setattr(safe_fetch.socket, "create_connection", connect)
    assert safe_fetch.first_reachable(["93.184.215.14"], 443) == "93.184.215.14"


def test_first_reachable_returns_the_first_address_when_none_answer(monkeypatch):
    def connect(address, timeout):
        raise OSError("refused")

    monkeypatch.setattr(safe_fetch.socket, "create_connection", connect)
    assert safe_fetch.first_reachable(["93.184.215.14", "93.184.215.15"], 443) == "93.184.215.14"


# Genuine sites that moved domains or sit behind bot protection

@pytest.mark.parametrize(
    "url, registered",
    [
        ("https://www.hdfc.bank.in/", "hdfc.bank.in"),
        ("https://onlinesbi.sbi.bank.in/", "sbi.bank.in"),
        ("https://www.kotak.bank.in/en/home.html", "kotak.bank.in"),
        ("https://example.fin.in/", "example.fin.in"),
    ],
)
def test_bank_in_and_fin_in_are_public_suffixes(url, registered):
    assert normalize_url(url).registered_domain == registered


@pytest.mark.parametrize("url", ["https://www.hdfc.bank.in/", "https://onlinesbi.sbi.bank.in/", "https://www.axis.bank.in/"])
def test_official_bank_in_domains_are_not_flagged(url):
    result = check_domain(normalize_url(url))
    assert not [item for item in result.indicators if item.severity.value in ("High", "Critical", "Medium")]


def test_redirect_to_another_domain_is_only_low_severity():
    from app.url_analysis.analyzer import analyze_redirects
    from app.url_analysis.safe_fetch import FetchResult, Hop

    fetch = FetchResult(
        hops=[Hop(url="https://twitter.com/", status=301, ip="1.1.1.1", location="https://x.com/"),
              Hop(url="https://x.com/", status=200, ip="1.1.1.2")],
        final_url="https://x.com/",
        final_status=200,
    )
    check, final = analyze_redirects(normalize_url("https://twitter.com"), fetch)
    assert final.registered_domain == "x.com"
    assert [item.severity.value for item in check.indicators if item.title == "Redirects to a different domain"] == ["Low"]


def _stalled_fetch(location):
    from app.url_analysis.safe_fetch import FetchResult, Hop

    return FetchResult(
        hops=[Hop(url="https://irctc.co.in/", status=301, ip="1.1.1.1", location=location)],
        error="Timed out connecting to the next host",
    )


def test_site_that_answered_before_a_same_domain_redirect_stalled_counts_as_reached():
    from app.url_analysis.analyzer import _reached_own_domain

    assert _reached_own_domain(normalize_url("https://irctc.co.in"), _stalled_fetch("https://www.irctc.co.in/"))


def test_stalled_redirect_to_another_domain_does_not_count_as_reached():
    from app.url_analysis.analyzer import _reached_own_domain

    assert not _reached_own_domain(normalize_url("https://irctc.co.in"), _stalled_fetch("https://evil.example/"))
