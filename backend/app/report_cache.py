"""Caches finished link reports, including the AI explanation, so repeat checks of the
same link are instant and do not spend AI credit. Messages are never cached, because
they can contain personal details."""

from .ai import add_ai_analysis, ai_enabled
from .cache import TTLCache
from .correlation import correlate, link_features
from .schemas import Classification, Report
from .url_analysis.analyzer import REPORT_CACHE_SECONDS, analyze_url_cached, mark_cached
from .url_analysis.classify import RECOMMENDED_ACTIONS
from .url_analysis.normalize import InvalidUrl, normalize_url

FINAL_CACHE = TTLCache("final link reports", REPORT_CACHE_SECONDS)


def link_report(raw: str, refresh: bool = False) -> Report:
    try:
        key = normalize_url(raw).url
    except InvalidUrl:
        return add_ai_analysis(analyze_url_cached(raw, refresh))

    if not refresh and (hit := FINAL_CACHE.get(key)):
        return mark_cached(hit[0], raw)

    report = analyze_url_cached(raw, refresh)
    report = correlate("link", key, link_features(report), report, RECOMMENDED_ACTIONS)
    report = add_ai_analysis(report)
    if _worth_keeping(report):
        FINAL_CACHE.set(key, report)
    return report


def _worth_keeping(report: Report) -> bool:
    """Do not keep results from failed checks, or ones where the AI explanation failed."""
    if report.classification == Classification.INCONCLUSIVE:
        return False
    return not (ai_enabled() and report.ai_summary is None)
