from dataclasses import dataclass, field

from ..schemas import Indicator, Severity


@dataclass
class CheckResult:
    """What every check returns, so the analyser can combine them the same way."""

    name: str
    completed: bool
    indicators: list[Indicator] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


def indicator(title: str, severity: Severity, evidence: str, source: str) -> Indicator:
    return Indicator(title=title, severity=severity, evidence=evidence, source=source)
