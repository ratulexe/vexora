"""Domain registration age (RDAP) and Certificate Transparency history (crt.sh).

These requests go to fixed public services, never to the submitted site.
"""

import json
from datetime import datetime, timedelta, timezone

import httpx

from ..schemas import Severity
from .common import CheckResult, indicator
from .distrusted_cas import find_distrusted
from .normalize import NormalizedUrl

RDAP_URL = "https://rdap.org/domain/{domain}"
CRT_SH_URL = "https://crt.sh/"
MAX_CT_BYTES = 3_000_000


def check_domain_age(url: NormalizedUrl) -> CheckResult:
    result = CheckResult(name="Domain age", completed=False)
    if url.is_ip or url.obfuscated_ip or not url.suffix:
        result.limitations.append("Domain age not checked: the link has no registered domain.")
        return result
    try:
        response = httpx.get(
            RDAP_URL.format(domain=url.registered_domain),
            timeout=httpx.Timeout(8.0),
            follow_redirects=True,
            headers={"Accept": "application/rdap+json"},
        )
        if response.status_code == 404:
            result.limitations.append(f"No registration record found for {url.registered_domain} (RDAP).")
            return result
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as error:
        result.limitations.append(f"Domain age unavailable (RDAP {type(error).__name__}).")
        return result

    registered = _event_date(data, "registration")
    if not registered:
        result.limitations.append("The registry did not publish a registration date.")
        return result

    age_days = (datetime.now(timezone.utc) - registered).days
    result.completed = True
    result.details = {"registered_on": registered.date().isoformat(), "age_days": age_days}
    if age_days < 30:
        severity = Severity.MEDIUM
        title = "Newly registered domain"
    elif age_days < 90:
        severity = Severity.LOW
        title = "Recently registered domain"
    else:
        return result
    result.indicators.append(
        indicator(
            title,
            severity,
            f"{url.registered_domain} was registered on {registered.date().isoformat()} ({age_days} days ago). "
            "Phishing domains are usually only days or weeks old.",
            "RDAP registration data",
        )
    )
    return result


def _event_date(data: dict, action: str) -> datetime | None:
    for event in data.get("events", []):
        if event.get("eventAction") == action and event.get("eventDate"):
            try:
                value = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
    return None


def check_certificate_transparency(url: NormalizedUrl) -> CheckResult:
    result = CheckResult(name="Certificate Transparency", completed=False)
    if url.is_ip or url.obfuscated_ip:
        return result
    try:
        with httpx.stream(
            "GET",
            CRT_SH_URL,
            params={"q": url.host, "output": "json", "exclude": "expired"},
            timeout=httpx.Timeout(6.0),
        ) as response:
            response.raise_for_status()
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_CT_BYTES:
                    result.limitations.append(
                        "Certificate Transparency: too many certificates to review for this host."
                    )
                    return result
        entries = json.loads(body or b"[]")
    except (httpx.HTTPError, ValueError) as error:
        result.limitations.append(f"Certificate Transparency logs unavailable (crt.sh {type(error).__name__}).")
        return result

    now = datetime.now(timezone.utc)
    recent = 0
    issuers: dict[str, int] = {}
    distrusted = None
    for entry in entries:
        issuer = entry.get("issuer_name", "")
        issuers[issuer] = issuers.get(issuer, 0) + 1
        issued = _parse_ct_date(entry.get("not_before"))
        if issued and now - issued < timedelta(days=30):
            recent += 1
        distrusted = distrusted or find_distrusted([issuer], issued.date() if issued else None)

    result.completed = True
    result.details = {
        "unexpired_certificates": len(entries),
        "issued_last_30_days": recent,
        "issuers": sorted(issuers, key=issuers.get, reverse=True)[:5],
    }
    if distrusted:
        result.indicators.append(
            indicator(
                f"Certificate from a distrusted CA logged for this host ({distrusted.name})",
                Severity.MEDIUM,
                f"Certificate Transparency logs show an unexpired certificate for {url.host} from "
                f"{distrusted.name}. {distrusted.reason}",
                "Certificate Transparency (crt.sh)",
            )
        )
    return result


def _parse_ct_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
