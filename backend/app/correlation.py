"""Threat correlation across reports (Module 4).

Each suspicious report is remembered for 7 days as a privacy-safe fingerprint:
its domains, redirect destinations, server addresses and impersonated brands,
plus keyed hashes of phone numbers, UPI IDs, email addresses and message wording.
Raw messages and contact details are never stored. The hash key is random and
only kept in memory, so the hashes cannot be reversed by guessing, even by
someone who sees them.

Connections are established by deterministic matching only. The AI may describe
them in its summary, but it never decides whether two reports are related.
Everything is lost when the server restarts; the on-chain registry is the
long-term record.
"""

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .message_analysis.extract import extract, redact
from .schemas import (
    Classification,
    Correlation,
    Indicator,
    RelatedReport,
    Report,
    Severity,
)
from .url_analysis.classify import sort_indicators
from .url_analysis.common import indicator
from .url_analysis.domain_checks import BRANDS
from .url_analysis.normalize import InvalidUrl, normalize_url

RETENTION_SECONDS = 7 * 24 * 3600
MAX_INCIDENTS = 2000
SIMILAR_WORDING = 0.5
SOURCE = "Vexora correlation"
RECORDED = {Classification.SUSPICIOUS, Classification.HIGH_RISK, Classification.CONFIRMED_MALICIOUS}

_KEY = secrets.token_bytes(32)
_lock = threading.Lock()
_incidents: "OrderedDict[str, Incident]" = OrderedDict()  # incident id -> incident
_by_key: dict[str, str] = {}  # fingerprint of the submission -> incident id


@dataclass
class Features:
    domains: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    servers: set[str] = field(default_factory=set)
    brands: set[str] = field(default_factory=set)
    contacts: set[str] = field(default_factory=set)  # "phone:<hash>", "upi:<hash>", "email:<hash>"
    wording: set[str] = field(default_factory=set)  # hashed 4-word shingles


@dataclass
class Incident:
    id: str
    kind: str
    classification: Classification
    first_seen: datetime
    last_seen_monotonic: float
    times_seen: int
    features: Features


def _hash(value: str) -> str:
    return hmac.new(_KEY, value.encode("utf-8"), hashlib.sha256).hexdigest()[:20]


# Building fingerprints


def link_features(report: Report) -> Features:
    details = report.details
    features = Features(brands=_brands(report.indicators))
    domain = details.get("Domain analysis", {}).get("registered_domain")
    if domain:
        features.domains.add(domain)
    redirects = details.get("Redirect analysis", {})
    for hop in redirects.get("redirect_chain", []):
        if hop.get("ip"):
            features.servers.add(hop["ip"])
    final = _registered_domain(redirects.get("final_url"))
    if final and final != domain:
        features.destinations.add(final)
    return features


def message_features(message: str, report: Report) -> Features:
    found = extract(message)
    features = Features(brands=set(report.details.get("organisations_mentioned", [])) | _brands(report.indicators))
    for link in report.details.get("links", []):
        if domain := _registered_domain(link.get("url")):
            features.domains.add(domain)
    features.contacts |= {f"phone:{_hash(phone[-10:])}" for phone in found.phones}
    features.contacts |= {f"upi:{_hash(upi.lower())}" for upi in found.upi_ids}
    features.contacts |= {f"email:{_hash(email.lower())}" for email in found.emails}
    words = re.findall(r"[a-z0-9\[\]_]+", redact(message).lower())
    if len(words) >= 8:
        features.wording = {_hash(" ".join(words[i : i + 4])) for i in range(len(words) - 3)}
    return features


def _brands(indicators: list[Indicator]) -> set[str]:
    text = " ".join(item.title.lower() for item in indicators)
    return {brand for brand in BRANDS if re.search(rf"\b{re.escape(brand)}\b", text)}


def _registered_domain(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return normalize_url(url).registered_domain
    except InvalidUrl:
        return None


# Matching


def _links(new: Features, old: Features) -> tuple[list[str], bool]:
    """Describes how two fingerprints connect. The flag is True for strong connections."""
    links, strong = [], False
    if shared := new.domains & old.domains:
        links.append(f"Same domain: {', '.join(sorted(shared))}")
        strong = True
    if shared := (new.destinations | new.domains) & (old.destinations | old.domains) - (new.domains & old.domains):
        links.append(f"Leads to the same site: {', '.join(sorted(shared))}")
        strong = True
    if shared := new.contacts & old.contacts:
        kinds = sorted({item.split(":", 1)[0] for item in shared})
        names = {"phone": "phone number", "upi": "UPI ID", "email": "email address"}
        links.append("Same " + " and ".join(names[kind] for kind in kinds))
        strong = True
    if new.wording and old.wording:
        overlap = len(new.wording & old.wording) / len(new.wording | old.wording)
        if overlap >= SIMILAR_WORDING:
            links.append(f"Similar wording ({overlap:.0%} overlap)")
            strong = True
    if shared := new.servers & old.servers:
        # A server address alone can be shared hosting or a CDN, so it is a weak link.
        links.append(f"Same server address: {', '.join(sorted(shared))} (could be shared hosting)")
    if shared := new.brands & old.brands:
        links.append(f"Same organisation impersonated or named: {', '.join(sorted(shared))}")
    return links, strong


def correlate(kind: str, key: str, features: Features, report: Report, actions: dict) -> Report:
    """Links this report to earlier suspicious ones, then records it if it is suspicious itself."""
    now = time.monotonic()
    key = _hash(f"{kind}:{key}")  # Only this keyed hash is stored, never the message or link itself.
    with _lock:
        _expire(now)
        own_id = _by_key.get(key)
        related: list[RelatedReport] = []
        strong_count = 0
        for incident in reversed(_incidents.values()):
            if incident.id == own_id:
                continue
            links, strong = _links(features, incident.features)
            if not links:
                continue
            strong_count += strong
            related.append(
                RelatedReport(
                    incident_id=incident.id,
                    kind=incident.kind,
                    classification=incident.classification.value,
                    first_seen=incident.first_seen,
                    times_seen=incident.times_seen,
                    links=links,
                    strong=strong,
                )
            )

    related.sort(key=lambda item: (not item.strong, -item.times_seen))
    if strong_count:
        report.indicators = sort_indicators(
            report.indicators
            + [
                indicator(
                    f"Linked to {strong_count} earlier suspicious report(s)",
                    Severity.MEDIUM,
                    "; ".join(dict.fromkeys(link for item in related if item.strong for link in item.links))[:400]
                    + ". The connections come from exact matches, not from the AI.",
                    SOURCE,
                )
            ]
        )
        if report.classification in (Classification.LOW_RISK, Classification.INCONCLUSIVE):
            report.classification = Classification.SUSPICIOUS
            report.recommended_actions = actions[Classification.SUSPICIOUS]

    incident_id = _record(key, kind, features, report.classification, now)
    report.correlation = Correlation(
        incident_id=incident_id,
        related=related[:10],
        strong_links=strong_count,
        retention="Suspicious reports are remembered for 7 days as fingerprints; raw messages and contact details are never stored.",
    )
    return report


def _record(key: str, kind: str, features: Features, classification: Classification, now: float) -> str | None:
    if classification not in RECORDED:
        return None
    with _lock:
        if (existing := _by_key.get(key)) and existing in _incidents:
            incident = _incidents[existing]
            incident.times_seen += 1
            incident.last_seen_monotonic = now
            incident.classification = classification
            _incidents.move_to_end(existing)
            return existing
        incident = Incident(
            id=secrets.token_hex(4),
            kind=kind,
            classification=classification,
            first_seen=datetime.now(timezone.utc),
            last_seen_monotonic=now,
            times_seen=1,
            features=features,
        )
        _incidents[incident.id] = incident
        _by_key[key] = incident.id
        while len(_incidents) > MAX_INCIDENTS:
            old_id, _ = _incidents.popitem(last=False)
            _forget(old_id)
        return incident.id


def _expire(now: float) -> None:
    for incident_id in [i.id for i in _incidents.values() if now - i.last_seen_monotonic > RETENTION_SECONDS]:
        del _incidents[incident_id]
        _forget(incident_id)


def _forget(incident_id: str) -> None:
    for key in [k for k, v in _by_key.items() if v == incident_id]:
        del _by_key[key]


def clear() -> None:
    with _lock:
        _incidents.clear()
        _by_key.clear()
