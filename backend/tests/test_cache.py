"""Tests for the in-memory result caches. No network access."""

from fastapi.testclient import TestClient

from app import cache as cache_module
from app import report_cache
from app.cache import TTLCache, cache_completed_checks
from app.main import app
from app.schemas import Severity
from app.url_analysis import analyzer
from app.url_analysis.common import CheckResult, indicator
from app.url_analysis.safe_fetch import FetchResult, Hop
from app.url_analysis.threat_intel import ThreatIntelResult

client = TestClient(app)


# The cache itself


def test_values_expire(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(cache_module.time, "monotonic", lambda: now[0])
    store = TTLCache("test", ttl_seconds=60)
    store.set("a", 1)
    assert store.get("a")[0] == 1
    now[0] += 61
    assert store.get("a") is None


def test_returns_copies_so_callers_cannot_change_stored_values():
    store = TTLCache("test", ttl_seconds=60)
    store.set("a", {"items": [1]})
    store.get("a")[0]["items"].append(2)
    assert store.get("a")[0] == {"items": [1]}


def test_oldest_entries_are_dropped_when_full():
    store = TTLCache("test", ttl_seconds=60, max_entries=2)
    for key in ("a", "b", "c"):
        store.set(key, key)
    assert store.get("a") is None
    assert store.get("c")[0] == "c"


def test_only_completed_checks_are_cached():
    store = TTLCache("test", ttl_seconds=60)
    calls = []

    @cache_completed_checks(store, key=lambda name: name)
    def check(name):
        calls.append(name)
        return CheckResult(name=name, completed=name == "ok")

    check("ok"), check("ok"), check("failed"), check("failed")
    assert calls == ["ok", "failed", "failed"]


# Link endpoint


def fake_network(monkeypatch, confirmed=False, reachable=True):
    calls = {"fetch": 0}

    def threat_intel(url):
        check = CheckResult(name="Threat intelligence", completed=True)
        if confirmed:
            check.indicators.append(indicator("Listed as an active phishing URL", Severity.CRITICAL, "", "OpenPhish"))
        return ThreatIntelResult(check=check, confirmed=confirmed, any_source_available=True)

    def fetch_chain(url):
        if not url.startswith("http://"):
            calls["fetch"] += 1
        if not reachable:
            return FetchResult(error="Timed out connecting")
        return FetchResult(hops=[Hop(url=url, status=200, ip="93.184.215.14")], final_url=url, final_status=200)

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(analyzer, "check_threat_intel", threat_intel)
    monkeypatch.setattr(analyzer, "fetch_redirect_chain", fetch_chain)
    monkeypatch.setattr(analyzer, "check_tls", lambda host, prefix="": CheckResult(name="TLS certificate", completed=True))
    monkeypatch.setattr(analyzer, "check_domain_age", lambda url: CheckResult(name="Domain age", completed=True))
    monkeypatch.setattr(
        analyzer, "check_certificate_transparency", lambda url: CheckResult(name="Certificate Transparency", completed=True)
    )
    return calls


def check_link(url: str, refresh: bool = False) -> dict:
    return client.post("/analyze/url", json={"url": url, "refresh": refresh}).json()


def test_repeat_check_reuses_the_saved_result(monkeypatch):
    calls = fake_network(monkeypatch)
    first = check_link("https://example.com")
    second = check_link("https://example.com")
    assert calls["fetch"] == 1
    assert first["from_cache"] is False
    assert second["from_cache"] is True
    assert second["analysed_at"] == first["analysed_at"]


def test_differently_written_links_share_a_result(monkeypatch):
    calls = fake_network(monkeypatch)
    check_link("https://example.com/")
    report = check_link("EXAMPLE.com")
    assert calls["fetch"] == 1
    assert report["input"] == "EXAMPLE.com"


def test_recheck_ignores_the_saved_result(monkeypatch):
    calls = fake_network(monkeypatch)
    check_link("https://example.com")
    report = check_link("https://example.com", refresh=True)
    assert calls["fetch"] == 2
    assert report["from_cache"] is False


def test_inconclusive_results_are_not_saved(monkeypatch):
    calls = fake_network(monkeypatch, reachable=False)
    assert check_link("https://example.com")["classification"] == "Inconclusive"
    check_link("https://example.com")
    assert calls["fetch"] == 2


def test_results_without_a_working_ai_explanation_are_not_saved(monkeypatch):
    calls = fake_network(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(report_cache, "add_ai_analysis", lambda report: report)  # AI "failed": no summary
    check_link("https://example.com")
    check_link("https://example.com")
    assert calls["fetch"] == 1  # The plain link report is reused...
    assert report_cache.FINAL_CACHE.get("https://example.com/") is None  # ...but not the incomplete final one.


def test_messages_are_never_stored(monkeypatch):
    fake_network(monkeypatch)
    message = "Hi Rahul, call me on 9876543210 about https://example.com"
    first = client.post("/analyze/message", json={"message": message}).json()
    second = client.post("/analyze/message", json={"message": message}).json()
    assert first["from_cache"] is False and second["from_cache"] is False
    assert first["analysed_at"] != second["analysed_at"]
    for store in cache_module._ALL:
        assert all("Rahul" not in str(key) and "9876543210" not in str(key) for key in store._items)
