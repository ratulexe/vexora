"""Offline tests for QR code investigation."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import qr_analysis
from app.main import app
from app.message_analysis import analyzer as message_analyzer
from app.qr_analysis import analyze_upi, content_type
from app.schemas import Classification, Report

client = TestClient(app)

REFUND_SCAM = (
    "upi://pay?pa=rk.7781@ybl&pn=SBI%20Refund%20Department&am=4999&tn=Scan%20to%20receive%20your%20KYC%20refund&cu=INR"
)
SHOP = "upi://pay?pa=sharmagrocery@okaxis&pn=Sharma%20Grocery&cu=INR"


def titles(report: Report) -> list[str]:
    return [item.title for item in report.indicators]


@pytest.mark.parametrize(
    "content, kind",
    [
        (REFUND_SCAM, "upi"),
        ("https://paypa1-secure-login.com/verify", "link"),
        ("example.com/login", "link"),
        ("WIFI:S:HomeNet;T:WPA;P:secret;;", "wifi"),
        ("Call 9876543210 to claim your prize", "text"),
    ],
)
def test_content_types(content, kind):
    assert content_type(content) == kind


def test_refund_scam_upi_code_is_high_risk():
    report = analyze_upi(REFUND_SCAM)
    assert report.classification == Classification.HIGH_RISK
    assert {"Claims you will receive money", "Payee name impersonates SBI", "Amount is pre-filled"} <= set(titles(report))
    assert report.details["qr"]["payee_address"] == "rk.7781@ybl"


def test_ordinary_shop_code_is_low_risk():
    report = analyze_upi(SHOP)
    assert report.classification == Classification.LOW_RISK
    assert titles(report) == ["Scanning this code sends money"]


def test_brand_using_its_own_upi_id_is_not_flagged():
    report = analyze_upi("upi://pay?pa=sbi.care@sbi&pn=SBI%20Customer%20Care&cu=INR")
    assert report.classification == Classification.LOW_RISK


def test_generic_authority_name_on_random_id_is_suspicious():
    report = analyze_upi("upi://pay?pa=helpdesk771@ybl&pn=Bank%20Customer%20Care&cu=INR")
    assert report.classification == Classification.SUSPICIOUS


def test_malformed_upi_id_is_flagged():
    assert "Malformed or missing UPI ID" in titles(analyze_upi("upi://pay?pa=nobody&pn=Shop"))


def test_wifi_password_is_never_returned(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    response = client.post("/analyze/qr", json={"content": "WIFI:S:HomeNet;T:WPA;P:supersecret;;"})
    assert response.status_code == 200
    assert "supersecret" not in response.text
    assert response.json()["input"] == "Wi-Fi network: HomeNet"


def test_links_use_the_link_analysis(monkeypatch):
    seen = []

    def fake_link_report(url):
        seen.append(url)
        return Report(
            input=url, classification=Classification.SUSPICIOUS, indicators=[], confidence="",
            recommended_actions=[], limitations=[], analysed_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(qr_analysis, "link_report", fake_link_report)
    report = qr_analysis.analyze_qr("https://paypa1-secure-login.com/verify")
    assert seen == ["https://paypa1-secure-login.com/verify"]
    assert report.details["qr_content_type"] == "link"


def test_upi_code_is_linked_to_an_earlier_scam_message(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(message_analyzer, "analyze_url", lambda url: None)
    client.post(
        "/analyze/message",
        json={"message": "You won Rs 25,00,000 in KBC lucky draw! Pay processing fee of Rs 5000 to rk.7781@ybl now."},
    )
    report = client.post("/analyze/qr", json={"content": REFUND_SCAM}).json()
    assert report["correlation"]["strong_links"] == 1
    assert "Same UPI ID" in report["correlation"]["related"][0]["links"]
