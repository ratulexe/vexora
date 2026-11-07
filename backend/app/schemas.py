"""The shared report format. Keep frontend/src/lib/report.ts in sync with this file."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Classification(str, Enum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive"


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Indicator(BaseModel):
    title: str
    severity: Severity
    evidence: str
    source: str


class SecurityFinding(BaseModel):
    issue: str
    severity: Severity
    evidence: str
    impact: str
    remediation: str


class SecurityAssessment(BaseModel):
    """Website security configuration (Module 5). Never affects the risk classification."""

    url: str
    tls_verdict: str
    findings: list[SecurityFinding]
    passed: list[str]
    limitations: list[str]


class RelatedReport(BaseModel):
    incident_id: str
    kind: str
    classification: str
    first_seen: datetime
    times_seen: int
    links: list[str]
    strong: bool


class Correlation(BaseModel):
    """Links to earlier suspicious reports (Module 4), found by exact matching."""

    incident_id: str | None
    related: list[RelatedReport]
    strong_links: int
    retention: str


class Report(BaseModel):
    input: str
    classification: Classification
    indicators: list[Indicator]
    confidence: str
    recommended_actions: list[str]
    limitations: list[str]
    analysed_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)
    ai_summary: str | None = None
    from_cache: bool = False
    security_assessment: SecurityAssessment | None = None
    correlation: Correlation | None = None


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    refresh: bool = False  # Ignore any saved result and check again


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
