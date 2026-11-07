"""Builds the off-chain report package and its on-chain commitment.

The package holds only what is safe to share: the classification, finding titles
and the domains involved. It never contains message text, quoted evidence, full
URLs or personal details. A random salt stops anyone guessing the contents from
the hash.

The commitment is keccak256 of the package's canonical JSON (keys sorted, no
spaces, UTF-8). frontend/src/lib/registry.ts must compute it the same way.
"""

import json
import secrets

from eth_utils import keccak

from ..schemas import Classification, Report
from ..url_analysis.normalize import InvalidUrl, normalize_url

SCHEMA = "vexora-threat-report/1"
CLASSIFICATION_CODES = {
    Classification.LOW_RISK: 0,
    Classification.SUSPICIOUS: 1,
    Classification.HIGH_RISK: 2,
    Classification.CONFIRMED_MALICIOUS: 3,
    Classification.INCONCLUSIVE: 4,
}
REGISTRABLE = {Classification.SUSPICIOUS, Classification.HIGH_RISK, Classification.CONFIRMED_MALICIOUS}
KIND_CODES = {"link": 0, "message": 1}


class NotRegistrable(ValueError):
    pass


def build_package(report: Report) -> dict:
    if report.classification not in REGISTRABLE:
        raise NotRegistrable("Only reports with warning signs (Suspicious or worse) can be added to the registry.")

    kind = "message" if "rules_matched" in report.details else "link"
    if kind == "link":
        domains = _domains([report.input])
    else:
        domains = _domains([link.get("url", "") for link in report.details.get("links", [])])

    return {
        "schema": SCHEMA,
        "kind": kind,
        "classification": report.classification.value,
        "domains": domains,
        "findings": [
            {"title": item.title, "severity": item.severity.value, "source": item.source}
            for item in report.indicators
            # AI-written findings quote the message, so they stay off the shared report.
            if not item.title.startswith("AI: ")
        ],
        "analysed_at": report.analysed_at.isoformat(),
        "salt": "0x" + secrets.token_hex(32),
    }


def canonical_json(package: dict) -> str:
    return json.dumps(package, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def commitment_of(package: dict) -> bytes:
    return keccak(canonical_json(package).encode("utf-8"))


def indicator_hash(domain: str | None) -> bytes:
    return keccak(domain.lower().encode("utf-8")) if domain else b"\x00" * 32


def classification_code(package: dict) -> int:
    return CLASSIFICATION_CODES[Classification(package["classification"])]


def kind_code(package: dict) -> int:
    return KIND_CODES[package["kind"]]


def _domains(urls: list[str]) -> list[str]:
    found = []
    for url in urls:
        try:
            found.append(normalize_url(url).registered_domain)
        except InvalidUrl:
            continue
    return list(dict.fromkeys(found))
