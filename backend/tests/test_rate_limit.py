"""Tests for per-visitor and shared AI rate limits."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from starlette.requests import Request

from app import ai, rate_limit
from app.main import app
from app.rate_limit import AI_CALLS, LINK_ANALYSIS, MESSAGE_ANALYSIS, RateLimiter, client_ip
from app.schemas import Classification, Report

client = TestClient(app)


def make_request(headers: dict[str, str], host: str = "10.0.0.1") -> Request:
    raw = [(key.lower().encode(), value.encode()) for key, value in headers.items()]
    return Request({"type": "http", "headers": raw, "client": (host, 1234)})


def test_window_slides(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: now[0])
    limiter = RateLimiter("test", limit=2, window_seconds=60)
    assert limiter.allow("a") and limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")
    now[0] = 61
    assert limiter.allow("a")


def test_client_ip_prefers_cloudflare_header():
    request = make_request({"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "6.6.6.6, 10.1.1.1"})
    assert client_ip(request) == "203.0.113.9"
    assert client_ip(make_request({"X-Forwarded-For": "198.51.100.4, 10.1.1.1"})) == "198.51.100.4"
    assert client_ip(make_request({})) == "10.0.0.1"


def test_message_checks_are_limited_per_visitor(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    headers = {"CF-Connecting-IP": "203.0.113.20"}
    for _ in range(MESSAGE_ANALYSIS.limit):
        assert client.post("/analyze/message", json={"message": "hello"}, headers=headers).status_code == 200
    response = client.post("/analyze/message", json={"message": "hello"}, headers=headers)
    assert response.status_code == 429
    assert "Too many message checks" in response.json()["detail"]
    other = client.post("/analyze/message", json={"message": "hello"}, headers={"CF-Connecting-IP": "203.0.113.21"})
    assert other.status_code == 200


def test_link_checks_are_limited_per_visitor(monkeypatch):
    for _ in range(LINK_ANALYSIS.limit):
        LINK_ANALYSIS.allow("203.0.113.30")
    response = client.post("/analyze/url", json={"url": "https://example.com"}, headers={"CF-Connecting-IP": "203.0.113.30"})
    assert response.status_code == 429


def test_ai_is_paused_when_the_shared_hourly_budget_is_spent(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    called = []
    monkeypatch.setattr(ai, "run_ai", lambda *args: called.append(1))
    for _ in range(AI_CALLS.limit):
        AI_CALLS.allow("all visitors")
    report = Report(
        input="x", classification=Classification.LOW_RISK, indicators=[], confidence="", recommended_actions=[],
        limitations=[], analysed_at=datetime.now(timezone.utc),
    )
    ai.add_ai_analysis(report)
    assert called == []
    assert "AI explanation paused" in report.limitations[-1]
