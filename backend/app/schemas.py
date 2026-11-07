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


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
