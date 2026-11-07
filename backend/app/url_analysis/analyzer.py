"""Runs every URL check and combines them into one report."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ..cache import TTLCache
from ..schemas import Classification, Report, Severity
from .classify import RECOMMENDED_ACTIONS, classify, evidence_coverage, sort_indicators
from .common import CheckResult, indicator
from .domain_checks import BRANDS, check_domain
from .domain_intel import check_certificate_transparency, check_domain_age
from .normalize import InvalidUrl, NormalizedUrl, normalize_url
from .safe_fetch import REDIRECT_STATUSES, FetchResult, fetch_redirect_chain
from .security_assessment import assess
from .threat_intel import check_threat_intel
from .tls_check import check_tls

SOURCE = "Vexora redirect analysis"
REPORT_CACHE_SECONDS = 30 * 60
REPORT_CACHE = TTLCache("link reports", REPORT_CACHE_SECONDS)

GENERAL_LIMITATIONS = [
    "Automated checks cannot prove that a site is safe.",
    "Page content, scripts and JavaScript or meta-refresh redirects are not analysed.",
]


def analyze_url_cached(raw: str, refresh: bool = False) -> Report:
    """analyze_url, reusing a result from the last 30 minutes for the same normalised link."""
    try:
        key = normalize_url(raw).url
    except InvalidUrl:
        return analyze_url(raw)
    if not refresh and (hit := REPORT_CACHE.get(key)):
        return mark_cached(hit[0], raw)
    report = analyze_url(raw)
    # Inconclusive usually means a check failed, so try again next time.
    if report.classification != Classification.INCONCLUSIVE:
        REPORT_CACHE.set(key, report)
    return report


def mark_cached(report: Report, raw: str) -> Report:
    report.input = raw
    report.from_cache = True
    return report


def analyze_url(raw: str) -> Report:
    analysed_at = datetime.now(timezone.utc)
    try:
        url = normalize_url(raw)
    except InvalidUrl as error:
        return Report(
            input=raw,
            classification=Classification.INCONCLUSIVE,
            indicators=[],
            confidence="No checks could run",
            recommended_actions=["Check that the link was copied correctly and try again."],
            limitations=[str(error)],
            analysed_at=analysed_at,
        )

    checks: list[CheckResult] = [check_domain(url)]
    limitations: list[str] = []
    site_reached = False
    security = None

    with ThreadPoolExecutor(max_workers=6) as pool:
        intel_future = pool.submit(check_threat_intel, url)
        age_future = pool.submit(check_domain_age, url)
        ct_future = None if url.is_ip or url.obfuscated_ip else pool.submit(check_certificate_transparency, url)

        intel = intel_future.result()
        if intel.confirmed:
            limitations.append(
                "The site itself was not contacted, because threat intelligence already identifies it as malicious."
            )
        else:
            fetch_future = pool.submit(fetch_redirect_chain, url.url)
            tls_future = pool.submit(check_tls, url.host)
            fetch = fetch_future.result()
            redirect_check, final = analyze_redirects(url, fetch)
            site_reached = fetch.final_status is not None
            tls_result = tls_future.result()
            checks += [redirect_check, tls_result]

            # Does the plain-HTTP address redirect to HTTPS? (Module 5)
            http_future = None
            if site_reached and final and final.scheme == "https" and not final.is_ip:
                http_future = pool.submit(fetch_redirect_chain, f"http://{final.host}/")

            if final and final.registered_domain != url.registered_domain:
                checks.append(check_domain(final, prefix="Final destination: "))
                tls_result = check_tls(final.host, prefix="Final destination: ")
                checks.append(tls_result)

            security = assess(fetch, tls_result, http_future.result() if http_future else None)

        checks.append(intel.check)
        checks.append(age_future.result())
        if ct_future:
            checks.append(ct_future.result())

    indicators = sort_indicators([item for check in checks for item in check.indicators])
    classification = classify(indicators, intel.confirmed, site_reached, intel.any_source_available)
    missing = [check.name for check in checks if not check.completed]
    for check in checks:
        limitations += check.limitations

    details = {"normalized_url": url.url}
    details.update({check.name: check.details for check in checks if check.details})

    return Report(
        input=raw,
        classification=classification,
        indicators=indicators,
        confidence=evidence_coverage(len(checks) - len(missing), len(checks), missing),
        recommended_actions=RECOMMENDED_ACTIONS[classification],
        limitations=list(dict.fromkeys(limitations + GENERAL_LIMITATIONS)),
        analysed_at=analysed_at,
        details=details,
        security_assessment=security,
    )


def analyze_redirects(url: NormalizedUrl, fetch: FetchResult) -> tuple[CheckResult, NormalizedUrl | None]:
    check = CheckResult(name="Redirect analysis", completed=False)

    def add(title: str, severity: Severity, evidence: str) -> None:
        check.indicators.append(indicator(title, severity, evidence, SOURCE))

    check.details = {
        "redirect_chain": [{"url": hop.url, "status": hop.status, "ip": hop.ip} for hop in fetch.hops],
        "final_url": fetch.final_url,
        "final_status": fetch.final_status,
    }

    if fetch.blocked:
        check.completed = True
        if fetch.hops:
            add(
                "Redirects to an internal network address",
                Severity.HIGH,
                f"After {len(fetch.hops)} hop(s) the link was blocked: {fetch.blocked}.",
            )
        else:
            add(
                "Link points to a private or internal address",
                Severity.MEDIUM,
                f"{fetch.blocked}. Public websites do not use these addresses.",
            )
        check.limitations.append("The site was not contacted, because it points to a non-public address.")
        return check, None

    if fetch.dns_failed and not fetch.hops:
        check.completed = True
        add(
            "Domain does not resolve",
            Severity.LOW,
            f"{url.host} has no DNS record. It may have been taken down, or never set up.",
        )
        check.limitations.append("The site could not be reached, so its redirects were not checked.")
        return check, None

    if not fetch.hops:
        check.limitations.append(f"The site could not be reached ({fetch.error}).")
        return check, None

    check.completed = True
    if fetch.error:
        if fetch.error.startswith("Stopped after"):
            add("Excessive redirects", Severity.MEDIUM, f"{fetch.error}. Redirect loops are used to evade scanners.")
        else:
            check.limitations.append(f"The redirect chain could not be completed ({fetch.error}).")

    hosts = [hop.url for hop in fetch.hops]
    redirects = sum(hop.status in REDIRECT_STATUSES for hop in fetch.hops)
    if redirects >= 3:
        add("Long redirect chain", Severity.LOW, f"{redirects} redirects: {' -> '.join(hosts)}.")

    for previous, current in zip(fetch.hops, fetch.hops[1:]):
        if previous.url.startswith("https://") and current.url.startswith("http://"):
            add(
                "Redirect downgrades from HTTPS to HTTP",
                Severity.MEDIUM,
                f"{previous.url} redirects to the unencrypted {current.url}.",
            )
            break

    final_url = fetch.final_url or (fetch.hops[-1].location and fetch.hops[-1].url)
    try:
        final = normalize_url(final_url) if final_url else None
    except InvalidUrl:
        final = None

    if final and final.registered_domain != url.registered_domain and not _same_brand(url, final):
        add(
            "Redirects to a different domain",
            Severity.MEDIUM,
            f"{url.host} sends visitors to {final.host}. Chain: {' -> '.join(hosts)}.",
        )
    return check, final


def _same_brand(first: NormalizedUrl, second: NormalizedUrl) -> bool:
    return any(
        first.registered_domain in official and second.registered_domain in official
        for official in BRANDS.values()
    )
