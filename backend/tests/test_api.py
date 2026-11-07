from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_url_returns_report_format():
    response = client.post("/analyze/url", json={"url": "https://example.com"})
    assert response.status_code == 200
    report = response.json()
    assert report["input"] == "https://example.com"
    assert report["classification"] == "Inconclusive"
    assert report["limitations"]
    assert report["analysed_at"]


def test_analyze_message_returns_report_format():
    response = client.post("/analyze/message", json={"message": "Share your OTP now"})
    assert response.status_code == 200
    assert response.json()["classification"] == "Inconclusive"


def test_empty_url_is_rejected():
    assert client.post("/analyze/url", json={"url": ""}).status_code == 422
