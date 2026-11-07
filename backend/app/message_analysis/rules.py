"""Fixed rules for common scam and social-engineering patterns.

Each finding quotes the part of the message that triggered it. Language patterns
alone are evidence of a *suspicious* message, not proof of fraud: urgency on its
own is only Low severity, so it can never make a message look dangerous by itself.
"""

import re
from dataclasses import dataclass

from ..schemas import Indicator, Severity
from ..url_analysis.common import indicator

SOURCE = "Vexora message rules"
NEGATION = re.compile(r"\b(?:do not|don't|dont|never|not to|no one|nobody|won't|will not)\b[^.!?\n]{0,30}$", re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    pattern: re.Pattern
    explanation: str
    negatable: bool = False


def _rx(*parts: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{part})" for part in parts), re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        "credential_request",
        "Asks for an OTP, PIN, password or card details",
        Severity.HIGH,
        _rx(
            r"\b(?:share|send|tell|provide|give|enter|reply(?: with)?|forward|confirm|submit|type)\b\W+(?:\w+\W+){0,4}?"
            r"(?:otp|one[- ]time password|upi pin|m-?pin|atm pin|\bpin\b|password|cvv|card (?:number|details)|"
            r"net ?banking (?:id|details|password)|login details|credentials|verification code|security code)",
        ),
        "Banks and genuine services never ask you to share these. Anyone who has them can take money from your account.",
        negatable=True,
    ),
    Rule(
        "remote_access",
        "Asks you to install a remote-access or unknown app",
        Severity.HIGH,
        _rx(
            r"\b(?:anydesk|teamviewer|quick ?support|rustdesk|ultraviewer|airdroid)\b",
            r"\binstall\b[^.!?\n]{0,40}\b(?:apk|app)\b",
            r"\.apk\b",
        ),
        "Remote-access apps and unknown APK files let a scammer see or control your phone, including banking apps.",
    ),
    Rule(
        "authority_threat",
        "Threatens arrest or legal action",
        Severity.HIGH,
        _rx(
            r"digital arrest",
            r"arrest warrant",
            r"\b(?:fir|police case|court case|legal case)\b[^.!?\n]{0,30}\b(?:against you|registered|filed|lodged)",
            r"money laundering",
            r"\b(?:cbi|ncb|narcotics|enforcement directorate|customs officer)\b",
            r"legal action will be (?:taken|initiated)",
        ),
        "Fake police or 'digital arrest' calls use fear to make people pay. Real agencies do not demand payment over phone or chat.",
    ),
    Rule(
        "payment_request",
        "Asks for an upfront payment or fee",
        Severity.MEDIUM,
        _rx(
            r"\b(?:registration|processing|verification|security|refundable|joining|delivery|customs|clearance|"
            r"activation|unlock|release|tax)\s+(?:fee|fees|charge|charges|deposit|amount)\b",
            r"\b(?:pay|transfer|deposit|send)\b\W+(?:\w+\W+){0,4}?(?:₹|rs\.?|inr|\d[\d,]*\s?(?:rupees|rs))",
        ),
        "Paying a fee to receive a prize, job, refund or parcel is a common scam pattern.",
    ),
    Rule(
        "account_threat",
        "Threatens to block your account or service",
        Severity.MEDIUM,
        _rx(
            r"\b(?:account|card|sim|number|connection|electricity|power|kyc|pan|wallet|service)\b\W+(?:\w+\W+){0,4}?"
            r"(?:will be |has been |is |be )?(?:blocked|suspended|deactivated|disconnected|frozen|closed|terminated|"
            r"restricted|cut|discontinued)",
        ),
        "Threats to block an account or cut off a service are used to rush people into acting without checking.",
    ),
    Rule(
        "kyc_update",
        "KYC, PAN or Aadhaar update request",
        Severity.MEDIUM,
        _rx(r"\b(?:kyc|pan|aadhaar|aadhar)\b\W+(?:\w+\W+){0,3}?(?:update|updation|verification|verify|expired|pending|link|re-?kyc)"),
        "Fake KYC update messages are one of the most common banking scams in India. Banks ask you to visit a branch or use their official app.",
    ),
    Rule(
        "prize_lure",
        "Prize, lottery or reward offer",
        Severity.MEDIUM,
        _rx(
            r"\byou(?:'ve| have)? (?:won|been selected)\b",
            r"\b(?:lottery|lucky draw|jackpot|kbc)\b",
            r"\bclaim (?:your|the) (?:prize|reward|gift|cashback|refund)\b",
            r"congratulations[^.!?\n]{0,40}\b(?:won|winner|selected)\b",
        ),
        "Unexpected prizes and rewards are used to collect personal details or a 'processing fee'.",
    ),
    Rule(
        "job_scam",
        "Easy-money job or task offer",
        Severity.MEDIUM,
        _rx(
            r"\bwork from home\b[^.!?\n]{0,60}\b(?:earn|income|salary|daily)\b",
            r"\bpart[- ]time (?:job|work)\b",
            r"\bearn\b[^.!?\n]{0,25}(?:₹|rs\.?|inr)?\s?\d[\d,]*[^.!?\n]{0,25}\b(?:daily|per day|a day|per hour|weekly)\b",
            r"\b(?:like|rate|review)\b[^.!?\n]{0,20}\b(?:youtube videos|videos|hotels|products)\b[^.!?\n]{0,40}\b(?:earn|pay|paid|₹|rs)",
            r"\btelegram\b[^.!?\n]{0,30}\btask",
            r"\bprepaid task\b",
        ),
        "Task-based job offers usually pay small amounts at first, then ask you to 'invest' larger sums you cannot withdraw.",
    ),
    Rule(
        "investment_scam",
        "Guaranteed or unrealistic investment returns",
        Severity.MEDIUM,
        _rx(
            r"guaranteed (?:returns?|profits?|income)",
            r"double your (?:money|investment)",
            r"\b\d{1,3}\s?% (?:daily|weekly|monthly|per day|per week|per month) (?:returns?|profits?)",
            r"risk[- ]free (?:investment|profit|returns?)",
            r"\b(?:vip|premium) (?:trading|stock|crypto) (?:group|signals|tips)\b",
        ),
        "No genuine investment can guarantee high returns. These offers are a common route to crypto and trading fraud.",
    ),
    Rule(
        "urgency",
        "Urgent or time-pressure language",
        Severity.LOW,
        _rx(
            r"\burgent(?:ly)?\b",
            r"\bimmediately\b",
            r"\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?)\b",
            r"\b(?:today only|last chance|last date|act now|final (?:notice|reminder|warning)|asap)\b",
            r"\bexpires? (?:today|tonight|soon)\b",
        ),
        "Urgency on its own does not make a message fraudulent, but scams use it to stop people checking.",
    ),
    Rule(
        "generic_greeting",
        "Generic greeting instead of your name",
        Severity.LOW,
        _rx(r"\bdear (?:customer|user|valued customer|sir/madam|account holder|beneficiary|candidate)\b"),
        "Organisations you deal with usually address you by name.",
    ),
)


def apply_rules(message: str) -> tuple[list[Indicator], list[str]]:
    """Returns the findings and the ids of the rules that matched."""
    found: list[Indicator] = []
    matched: list[str] = []
    for rule in RULES:
        quote = _first_match(rule, message)
        if quote is None:
            continue
        matched.append(rule.id)
        found.append(indicator(rule.title, rule.severity, f'"{quote}". {rule.explanation}', SOURCE))
    return found, matched


def _first_match(rule: Rule, message: str) -> str | None:
    for match in rule.pattern.finditer(message):
        # Skip warnings such as "Do not share your OTP with anyone".
        if rule.negatable and NEGATION.search(message[max(0, match.start() - 40) : match.start()] + " "):
            continue
        return _snippet(message, match.start(), match.end())
    return None


def _snippet(message: str, start: int, end: int) -> str:
    left = max(0, start - 30)
    right = min(len(message), end + 30)
    text = " ".join(message[left:right].split())
    return ("..." if left > 0 else "") + text + ("..." if right < len(message) else "")
