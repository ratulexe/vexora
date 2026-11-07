"""Deterministic risk classification. The AI may explain the result but never sets it."""

from ..schemas import Classification, Indicator, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

RECOMMENDED_ACTIONS = {
    Classification.CONFIRMED_MALICIOUS: [
        "Do not open this link or enter any information on it.",
        "If you already entered a password, OTP or card details, change the password and contact your bank or the service immediately.",
        "Report it at cybercrime.gov.in or call the 1930 cybercrime helpline (India).",
    ],
    Classification.HIGH_RISK: [
        "Do not enter passwords, OTPs or payment details on this site.",
        "Reach the organisation through its official app or by typing its address yourself.",
        "If you received this link unexpectedly, report it rather than forwarding it.",
    ],
    Classification.SUSPICIOUS: [
        "Treat this link with caution until you have verified it through an official channel.",
        "Do not enter passwords, OTPs or payment details unless you are sure the site is genuine.",
    ],
    Classification.INCONCLUSIVE: [
        "Not enough evidence could be collected. Do not treat this result as meaning the link is safe.",
        "Verify the link through an official channel before entering any information.",
    ],
    Classification.LOW_RISK: [
        "No significant warning signs were found in the available checks, but this does not prove the site is safe.",
        "Never share OTPs or passwords in response to an unexpected message, whatever the link looks like.",
    ],
}


def classify(
    indicators: list[Indicator], confirmed: bool, site_reached: bool, threat_intel_available: bool
) -> Classification:
    if confirmed:
        return Classification.CONFIRMED_MALICIOUS
    high = sum(item.severity in (Severity.HIGH, Severity.CRITICAL) for item in indicators)
    medium = sum(item.severity == Severity.MEDIUM for item in indicators)
    if high >= 2 or (high >= 1 and medium >= 2):
        return Classification.HIGH_RISK
    if high or medium:
        return Classification.SUSPICIOUS
    if not site_reached or not threat_intel_available:
        return Classification.INCONCLUSIVE
    return Classification.LOW_RISK


def evidence_coverage(completed: int, total: int, missing: list[str]) -> str:
    ratio = completed / total if total else 0
    level = "High" if ratio >= 0.85 else "Medium" if ratio >= 0.5 else "Low"
    text = f"{level} ({completed} of {total} checks completed"
    return f"{text}; not completed: {', '.join(missing)})" if missing else f"{text})"


def sort_indicators(indicators: list[Indicator]) -> list[Indicator]:
    seen = set()
    unique = []
    for item in indicators:
        key = (item.title, item.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return sorted(unique, key=lambda item: SEVERITY_ORDER.index(item.severity))
