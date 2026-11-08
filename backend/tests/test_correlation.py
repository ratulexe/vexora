"""Offline tests for threat correlation (Module 4)."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app import correlation
from app.correlation import correlate, link_features
from app.main import app
from app.message_analysis import analyzer as message_analyzer
from app.schemas import Classification, Report, Severity
from app.url_analysis.classify import RECOMMENDED_ACTIONS
from app.url_analysis.common import indicator

client = TestClient(app)

SCAM_A = "Congratulations! You won Rs 25,00,000 in KBC lucky draw. Pay processing fee of Rs 5000 to refund@ybl now."
SCAM_B = "Your parcel is held at customs. Pay clearance charges of Rs 1200 to refund@ybl to release it today."


def check_message(message: str, monkeypatch) -> dict:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        message_analyzer,
        "analyze_url",
        lambda url: Report(
            input=url, classification=Classification.LOW_RISK, indicators=[], confidence="",
            recommended_actions=[], limitations=[], analysed_at=datetime.now(timezone.utc),
        ),
    )
    return client.post("/analyze/message", json={"message": message}).json()


def test_messages_with_the_same_upi_id_are_linked(monkeypatch):
    first = check_message(SCAM_A, monkeypatch)
    second = check_message(SCAM_B, monkeypatch)
    assert first["correlation"]["related"] == []
    related = second["correlation"]["related"]
    assert related[0]["incident_id"] == first["correlation"]["incident_id"]
    assert "Same UPI ID" in related[0]["links"]
    assert second["correlation"]["strong_links"] == 1
    assert any(item["title"] == "Linked to 1 earlier suspicious report(s)" for item in second["indicators"])


def test_contact_details_and_text_are_never_stored_raw(monkeypatch):
    check_message(SCAM_A + " Call 9876543210.", monkeypatch)
    stored = repr(list(correlation._incidents.values())) + repr(correlation._by_key)
    for raw in ("refund@ybl", "9876543210", "lucky draw", "KBC"):
        assert raw not in stored


def test_messages_from_the_same_template_are_linked_by_wording(monkeypatch):
    template = "Dear customer, your account will be blocked today. Update your KYC immediately by calling {} or visit the branch."
    check_message(template.format("9876543210"), monkeypatch)
    second = check_message(template.format("9123456780"), monkeypatch)
    links = second["correlation"]["related"][0]["links"]
    assert any(link.startswith("Similar wording") for link in links)


def test_reusing_a_scammers_phone_number_raises_the_risk(monkeypatch):
    check_message(SCAM_A + " Questions? Call 9876543210.", monkeypatch)
    quiet = check_message("Hello, please call 9876543210 when you are free.", monkeypatch)
    assert quiet["classification"] == "Suspicious"
    assert "Same phone number" in quiet["correlation"]["related"][0]["links"]


def test_benign_messages_are_not_recorded(monkeypatch):
    report = check_message("Hi Rahul, the meeting is moved to 4pm tomorrow.", monkeypatch)
    assert report["correlation"]["incident_id"] is None
    assert correlation._incidents == {}


def test_repeat_submission_is_not_linked_to_itself(monkeypatch):
    first = check_message(SCAM_A, monkeypatch)
    again = check_message(SCAM_A, monkeypatch)
    assert again["correlation"]["related"] == []
    assert again["correlation"]["incident_id"] == first["correlation"]["incident_id"]
    assert correlation._incidents[first["correlation"]["incident_id"]].times_seen == 2


def link_report(url: str, domain: str, final_url: str, ip: str, brand_title: str | None = None) -> Report:
    indicators = []
    if brand_title:
        indicators.append(indicator(brand_title, Severity.HIGH, "", "test"))
    return Report(
        input=url, classification=Classification.SUSPICIOUS if brand_title else Classification.LOW_RISK,
        indicators=indicators, confidence="", recommended_actions=[], limitations=[],
        analysed_at=datetime.now(timezone.utc),
        details={
            "Domain analysis": {"registered_domain": domain},
            "Redirect analysis": {"redirect_chain": [{"url": url, "ip": ip}], "final_url": final_url},
        },
    )


def test_links_that_redirect_to_the_same_site_are_linked():
    first = link_report("https://bit.ly/a", "bit.ly", "https://login-verify.example.net/", "1.1.1.1", "Uses the name 'paypal' on an unofficial domain")
    correlate("link", "https://bit.ly/a", link_features(first), first, RECOMMENDED_ACTIONS)
    second = link_report("https://tinyurl.com/b", "tinyurl.com", "https://login-verify.example.net/x", "2.2.2.2")
    result = correlate("link", "https://tinyurl.com/b", link_features(second), second, RECOMMENDED_ACTIONS)
    assert "Leads to the same site: example.net" in result.correlation.related[0].links
    assert result.classification == Classification.SUSPICIOUS
    assert result.recommended_actions == RECOMMENDED_ACTIONS[Classification.SUSPICIOUS]


def test_same_brand_alone_is_a_weak_link_without_a_finding():
    first = link_report("https://paypa1-a.com", "paypa1-a.com", "https://paypa1-a.com/", "1.1.1.1", "Uses the name 'paypal' on an unofficial domain")
    correlate("link", "a", link_features(first), first, RECOMMENDED_ACTIONS)
    second = link_report("https://paypa1-b.com", "paypa1-b.com", "https://paypa1-b.com/", "3.3.3.3", "Impersonates paypal with look-alike characters")
    result = correlate("link", "b", link_features(second), second, RECOMMENDED_ACTIONS)
    related = result.correlation.related[0]
    assert related.strong is False
    assert related.links == ["Same organisation impersonated or named: paypal"]
    assert not any(item.title.startswith("Linked to") for item in result.indicators)


def test_records_expire(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(correlation.time, "monotonic", lambda: now[0])
    first = link_report("https://paypa1-a.com", "paypa1-a.com", "https://paypa1-a.com/", "1.1.1.1", "Uses the name 'paypal' on an unofficial domain")
    correlate("link", "a", link_features(first), first, RECOMMENDED_ACTIONS)
    now[0] += correlation.RETENTION_SECONDS + 1
    second = link_report("https://paypa1-a.com/x", "paypa1-a.com", "https://paypa1-a.com/x", "1.1.1.1", "Uses the name 'paypal' on an unofficial domain")
    assert correlate("link", "b", link_features(second), second, RECOMMENDED_ACTIONS).correlation.related == []
