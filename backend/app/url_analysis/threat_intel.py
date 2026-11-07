"""Known-threat lookups. A source that is down or not configured is reported as a
limitation, never as a clean result."""

import os
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from ..schemas import Severity
from .common import CheckResult, indicator
from .normalize import NormalizedUrl

TIMEOUT = httpx.Timeout(8.0)
# openphish.com/feed.txt redirects here.
OPENPHISH_FEED = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
OPENPHISH_REFRESH_SECONDS = 30 * 60
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


@dataclass
class ThreatIntelResult:
    check: CheckResult
    confirmed: bool = False
    sources: dict[str, str] = field(default_factory=dict)  # Source name -> what happened
    any_source_available: bool = False


def check_threat_intel(url: NormalizedUrl) -> ThreatIntelResult:
    result = ThreatIntelResult(check=CheckResult(name="Threat intelligence", completed=False))
    for lookup in (_openphish, _urlhaus, _safe_browsing):
        name, status = lookup(url, result)
        result.sources[name] = status
        if status in ("match", "no match", "host reported"):
            result.any_source_available = True
        elif status != "not configured":
            result.check.limitations.append(f"{name} was unavailable ({status}).")

    not_configured = [name for name, status in result.sources.items() if status == "not configured"]
    if not_configured:
        result.check.limitations.append(f"Not configured (no API key): {', '.join(not_configured)}.")
    result.check.completed = result.any_source_available
    result.check.details = {"sources": result.sources}
    if result.any_source_available and not result.check.indicators:
        result.check.limitations.append(
            "No known-threat match. Threat feeds only list reported sites, so this does not mean the link is safe."
        )
    return result


# OpenPhish community feed: free, no key, refreshed every 30 minutes.
_feed_lock = threading.Lock()
_feed: dict = {"fetched_at": 0.0, "urls": set(), "hosts": set()}


def _openphish(url: NormalizedUrl, result: ThreatIntelResult) -> tuple[str, str]:
    name = "OpenPhish"
    try:
        urls, hosts = _load_openphish()
    except httpx.HTTPError as error:
        return name, type(error).__name__

    candidates = {url.url, url.url.rstrip("/"), url.original.strip(), url.original.strip().rstrip("/")}
    if candidates & urls:
        result.confirmed = True
        result.check.indicators.append(
            indicator(
                "Listed as an active phishing URL",
                Severity.CRITICAL,
                "This exact URL is in the OpenPhish community phishing feed.",
                name,
            )
        )
        return name, "match"
    if url.host in hosts:
        result.check.indicators.append(
            indicator(
                "Other phishing URLs reported on this host",
                Severity.MEDIUM,
                f"OpenPhish lists phishing pages on {url.host}. If the host is shared (for example a site "
                "builder), other pages on it may be unrelated.",
                name,
            )
        )
        return name, "host reported"
    return name, "no match"


def _load_openphish() -> tuple[set[str], set[str]]:
    with _feed_lock:
        if time.time() - _feed["fetched_at"] < OPENPHISH_REFRESH_SECONDS:
            return _feed["urls"], _feed["hosts"]
        response = httpx.get(OPENPHISH_FEED, timeout=TIMEOUT, follow_redirects=True)
        response.raise_for_status()
        lines = [line.strip() for line in response.text.splitlines() if line.strip().startswith("http")]
        if not lines:
            raise httpx.DecodingError("the feed contained no URLs")
        urls = set(lines) | {line.rstrip("/") for line in lines}
        hosts = {(urlsplit(item).hostname or "").lower() for item in urls} - {""}
        _feed.update(fetched_at=time.time(), urls=urls, hosts=hosts)
        return urls, hosts


def _urlhaus(url: NormalizedUrl, result: ThreatIntelResult) -> tuple[str, str]:
    name = "URLhaus"
    key = os.getenv("URLHAUS_AUTH_KEY")
    if not key:
        return name, "not configured"
    headers = {"Auth-Key": key}
    try:
        response = httpx.post(f"{URLHAUS_API}/url/", data={"url": url.url}, headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        if data.get("query_status") == "ok":
            result.confirmed = True
            result.check.indicators.append(
                indicator(
                    "Listed as a malware distribution URL",
                    Severity.CRITICAL,
                    f"URLhaus lists this URL (status: {data.get('url_status')}, threat: {data.get('threat')}, "
                    f"added {data.get('date_added')}).",
                    name,
                )
            )
            return name, "match"

        response = httpx.post(f"{URLHAUS_API}/host/", data={"host": url.host}, headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        if data.get("query_status") == "ok" and data.get("url_count"):
            result.check.indicators.append(
                indicator(
                    "Host has distributed malware",
                    Severity.HIGH,
                    f"URLhaus has {data.get('url_count')} malware URLs on {url.host}.",
                    name,
                )
            )
            return name, "host reported"
        return name, "no match"
    except (httpx.HTTPError, ValueError) as error:
        return name, type(error).__name__


def _safe_browsing(url: NormalizedUrl, result: ThreatIntelResult) -> tuple[str, str]:
    name = "Google Safe Browsing"
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return name, "not configured"
    body = {
        "client": {"clientId": "vexora", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url.url}],
        },
    }
    try:
        response = httpx.post(SAFE_BROWSING_API, params={"key": key}, json=body, timeout=TIMEOUT)
        response.raise_for_status()
        matches = response.json().get("matches", [])
    except (httpx.HTTPError, ValueError) as error:
        return name, type(error).__name__
    if matches:
        result.confirmed = True
        types = sorted({match.get("threatType", "UNKNOWN") for match in matches})
        result.check.indicators.append(
            indicator(
                "Flagged by Google Safe Browsing",
                Severity.CRITICAL,
                f"Google Safe Browsing reports: {', '.join(types)}.",
                name,
            )
        )
        return name, "match"
    return name, "no match"
