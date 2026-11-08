"""Offline tests for the website security assessment (Module 5)."""

from app.schemas import Severity
from app.url_analysis.common import CheckResult, indicator
from app.url_analysis.safe_fetch import FetchResult, Hop
from app.url_analysis.security_assessment import assess, tls_verdict

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "server": "nginx",
}


def fetched(url="https://shop.example.com/", headers=None, cookies=None):
    hop = Hop(url=url, status=200, ip="93.184.215.14", headers=headers or {}, cookies=cookies or [])
    return FetchResult(hops=[hop], final_url=url, final_status=200)


def tls(trusted=True, legacy=False, titles=()):
    check = CheckResult(name="TLS certificate", completed=True, details={"trusted": trusted, "legacy_tls_accepted": legacy})
    check.indicators = [indicator(title, Severity.HIGH, "", "test") for title in titles]
    return check


def redirected_to_https():
    return FetchResult(final_url="https://shop.example.com/", final_status=200)


def issues(assessment):
    return [item.issue for item in assessment.findings]


def test_well_configured_site_has_no_findings():
    cookie = "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    result = assess(fetched(headers=GOOD_HEADERS, cookies=[cookie]), tls(), redirected_to_https())
    assert result.findings == []
    assert result.tls_verdict == "Valid"
    assert "HTTP redirects to HTTPS" in result.passed


def test_missing_headers_are_reported_with_impact_and_fix():
    result = assess(fetched(), tls(), redirected_to_https())
    assert {
        "No HTTP Strict Transport Security (HSTS)",
        "No Content-Security-Policy",
        "No clickjacking protection",
        "No X-Content-Type-Options: nosniff",
        "No Referrer-Policy",
    } <= set(issues(result))
    for item in result.findings:
        assert item.evidence and item.impact and item.remediation


def test_plain_http_page_is_high_severity_and_tls_not_used():
    result = assess(fetched(url="http://shop.example.com/", headers=GOOD_HEADERS), tls(), None)
    assert result.findings[0].issue == "Page is served over plain HTTP"
    assert result.findings[0].severity == Severity.HIGH
    assert result.tls_verdict.startswith("Not used")


def test_short_hsts_missing_https_redirect_weak_cookies_and_versions():
    headers = dict(GOOD_HEADERS, **{"strict-transport-security": "max-age=600", "server": "Apache/2.4.49"})
    http_check = FetchResult(final_url="http://shop.example.com/", final_status=200)
    result = assess(fetched(headers=headers, cookies=["id=1; Path=/"]), tls(), http_check)
    assert {
        "HSTS lifetime is short",
        "HTTP version does not redirect to HTTPS",
        "Cookies without protective flags",
        "Server software version disclosed",
    } <= set(issues(result))


def test_outdated_tls_versions_are_reported():
    result = assess(fetched(headers=GOOD_HEADERS), tls(legacy=True), redirected_to_https())
    assert issues(result) == ["Server accepts outdated TLS 1.0/1.1"]


def test_unreachable_site_has_no_assessment():
    assert assess(FetchResult(error="Timed out"), tls(), None) is None


def test_tls_verdicts():
    assert tls_verdict(tls()) == "Valid"
    assert tls_verdict(tls(trusted=False)) == "Suspicious"
    assert tls_verdict(tls(titles=["Weak public key"])) == "Suspicious"
    assert tls_verdict(tls(titles=["Issued by a distrusted certificate authority (DigiNotar)"])) == "Potentially compromised"
    assert tls_verdict(CheckResult(name="TLS certificate", completed=True, details={"https_available": False})) == "HTTPS not available"
    assert tls_verdict(None) == "Not checked"
