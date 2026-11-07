from fastapi.testclient import TestClient

from app.main import app
from app.schemas import Severity
from app.url_analysis import analyzer
from app.url_analysis.common import CheckResult, indicator
from app.url_analysis.safe_fetch import FetchResult, Hop
from app.url_analysis.threat_intel import ThreatIntelResult

client = TestClient(app)


def fake_network(monkeypatch, confirmed=False, fetch=None):
    """Replace every network-facing check, so these tests run offline."""

    def threat_intel(url):
        check = CheckResult(name="Threat intelligence", completed=True)
        if confirmed:
            check.indicators.append(indicator("Listed as an active phishing URL", Severity.CRITICAL, "", "OpenPhish"))
        return ThreatIntelResult(check=check, confirmed=confirmed, any_source_available=True)

    calls = {"fetch": 0}

    def fetch_chain(url):
        calls["fetch"] += 1
        return fetch or FetchResult(hops=[Hop(url=url, status=200, ip="93.184.215.14")], final_url=url, final_status=200)

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(analyzer, "check_threat_intel", threat_intel)
    monkeypatch.setattr(analyzer, "fetch_redirect_chain", fetch_chain)
    monkeypatch.setattr(analyzer, "check_tls", lambda host, prefix="": CheckResult(name=f"{prefix}TLS certificate", completed=True))
    monkeypatch.setattr(analyzer, "check_domain_age", lambda url: CheckResult(name="Domain age", completed=True))
    monkeypatch.setattr(
        analyzer, "check_certificate_transparency", lambda url: CheckResult(name="Certificate Transparency", completed=True)
    )
    return calls


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_benign_url_is_low_risk(monkeypatch):
    fake_network(monkeypatch)
    response = client.post("/analyze/url", json={"url": "https://example.com"})
    assert response.status_code == 200
    report = response.json()
    assert report["classification"] == "Low Risk"
    assert "Automated checks cannot prove that a site is safe." in report["limitations"]
    assert report["details"]["normalized_url"] == "https://example.com/"


def test_impersonation_is_flagged(monkeypatch):
    fake_network(monkeypatch)
    report = client.post("/analyze/url", json={"url": "https://paypa1-secure-login.com"}).json()
    assert report["classification"] == "Suspicious"
    assert report["indicators"][0]["severity"] == "High"


def test_confirmed_malicious_site_is_not_contacted(monkeypatch):
    calls = fake_network(monkeypatch, confirmed=True)
    report = client.post("/analyze/url", json={"url": "https://phish.example.net/login"}).json()
    assert report["classification"] == "Confirmed Malicious"
    assert calls["fetch"] == 0


def test_redirect_to_other_domain_is_reported(monkeypatch):
    fetch = FetchResult(
        hops=[
            Hop(url="https://bit.ly/x", status=301, ip="67.199.248.10", location="https://login-verify.example.org/"),
            Hop(url="https://login-verify.example.org/", status=200, ip="93.184.215.14"),
        ],
        final_url="https://login-verify.example.org/",
        final_status=200,
    )
    fake_network(monkeypatch, fetch=fetch)
    report = client.post("/analyze/url", json={"url": "https://bit.ly/x"}).json()
    titles = [item["title"] for item in report["indicators"]]
    assert "Redirects to a different domain" in titles
    assert report["classification"] == "Suspicious"


def test_internal_address_is_blocked(monkeypatch):
    fake_network(monkeypatch, fetch=FetchResult(blocked="localhost resolves to a non-public address (127.0.0.1)"))
    report = client.post("/analyze/url", json={"url": "http://localhost/admin"}).json()
    titles = [item["title"] for item in report["indicators"]]
    assert "Link points to a private or internal address" in titles


def test_invalid_url_is_inconclusive():
    report = client.post("/analyze/url", json={"url": "javascript:alert(1)"}).json()
    assert report["classification"] == "Inconclusive"


def test_analyze_message_flags_credential_request(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    response = client.post("/analyze/message", json={"message": "Share your OTP now"})
    assert response.status_code == 200
    report = response.json()
    assert report["classification"] == "Suspicious"
    assert report["indicators"][0]["title"] == "Asks for an OTP, PIN, password or card details"


def test_empty_url_is_rejected():
    assert client.post("/analyze/url", json={"url": ""}).status_code == 422
