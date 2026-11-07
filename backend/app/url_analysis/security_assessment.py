"""Website security assessment (Module 5): passive checks of configuration only.

These findings describe how well a site protects its visitors. They are kept
separate from the phishing indicators: missing headers are a weakness, not a sign
of fraud, so they never change the risk classification. Nothing here probes for
hidden files or exploits anything; it only reads headers the site sent anyway and
the TLS details already collected.
"""

import re

from ..schemas import SecurityAssessment, SecurityFinding, Severity
from .common import CheckResult
from .safe_fetch import FetchResult

HSTS_MIN_SECONDS = 180 * 24 * 3600
VERSION_PATTERN = re.compile(r"\d+(?:\.\d+)+")

LIMITATIONS = [
    "Only passive checks were run: response headers and TLS details. Hidden files and endpoints were not probed.",
    "Page content was not read, so mixed content and outdated JavaScript libraries were not checked.",
    "Known vulnerabilities are not looked up; software versions are only flagged when the server discloses them.",
]


def assess(fetch: FetchResult, tls: CheckResult | None, http_check: FetchResult | None) -> SecurityAssessment | None:
    """Assess the final page the link led to. Returns None if the site could not be reached."""
    if fetch.final_status is None or not fetch.hops:
        return None
    final = fetch.hops[-1]
    https = final.url.lower().startswith("https://")
    headers = {name.lower(): value for name, value in final.headers.items()}
    findings: list[SecurityFinding] = []
    passed: list[str] = []

    def finding(issue, severity, evidence, impact, remediation):
        findings.append(
            SecurityFinding(issue=issue, severity=severity, evidence=evidence, impact=impact, remediation=remediation)
        )

    if not https:
        finding(
            "Page is served over plain HTTP",
            Severity.HIGH,
            f"The final page {final.url} is not encrypted.",
            "Anyone on the network can read or change what visitors see and send, including passwords.",
            "Serve the site only over HTTPS and redirect all HTTP requests to HTTPS.",
        )
    else:
        _check_hsts(headers, finding, passed)
        _check_http_redirect(final.url, http_check, finding, passed)

    _check_header(
        headers, "content-security-policy", finding, passed,
        label="Content-Security-Policy",
        issue="No Content-Security-Policy",
        severity=Severity.MEDIUM,
        impact="If an attacker injects script into a page, the browser has no rules to block it (cross-site scripting).",
        remediation="Add a Content-Security-Policy header that limits where scripts can load from.",
    )
    frame_protected = "x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", "")
    if frame_protected:
        passed.append("Clickjacking protection (X-Frame-Options or frame-ancestors)")
    else:
        finding(
            "No clickjacking protection",
            Severity.MEDIUM,
            "Neither X-Frame-Options nor a CSP frame-ancestors rule was sent.",
            "Another site can load this page in an invisible frame and trick visitors into clicking things.",
            "Send X-Frame-Options: DENY, or Content-Security-Policy: frame-ancestors 'none'.",
        )
    if headers.get("x-content-type-options", "").strip().lower() == "nosniff":
        passed.append("X-Content-Type-Options: nosniff")
    else:
        finding(
            "No X-Content-Type-Options: nosniff",
            Severity.LOW,
            "The header is missing or not set to nosniff.",
            "Browsers may guess file types, which can let uploaded files run as scripts.",
            "Send X-Content-Type-Options: nosniff.",
        )
    _check_header(
        headers, "referrer-policy", finding, passed,
        label="Referrer-Policy",
        issue="No Referrer-Policy",
        severity=Severity.LOW,
        impact="Full page addresses, which can contain private details, may be leaked to other sites.",
        remediation="Send Referrer-Policy: strict-origin-when-cross-origin, or stricter.",
    )

    _check_cookies(final.cookies, https, finding, passed)
    _check_version_disclosure(headers, finding, passed)
    _check_tls(tls, finding)

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    findings.sort(key=lambda item: order.index(item.severity))
    return SecurityAssessment(
        url=final.url,
        tls_verdict=tls_verdict(tls) if https else "Not used: the page is served over plain HTTP",
        findings=findings,
        passed=passed,
        limitations=LIMITATIONS,
    )


def tls_verdict(tls: CheckResult | None) -> str:
    """The certificate verdict Module 2 asks for. A valid certificate never means the site is safe."""
    if tls is None or not tls.completed:
        return "Not checked"
    if tls.details.get("https_available") is False:
        return "HTTPS not available"
    titles = " ".join(item.title for item in tls.indicators)
    if "distrusted certificate authority" in titles:
        return "Potentially compromised"
    if not tls.details.get("trusted", False) or any(
        word in titles for word in ("Weak", "does not match", "do not include", "Outdated")
    ):
        return "Suspicious"
    return "Valid"


def _check_header(headers, name, finding, passed, *, label, issue, severity, impact, remediation):
    if name in headers:
        passed.append(label)
    else:
        finding(issue, severity, f"The {name} header was not sent.", impact, remediation)


def _check_hsts(headers, finding, passed):
    value = headers.get("strict-transport-security")
    if not value:
        finding(
            "No HTTP Strict Transport Security (HSTS)",
            Severity.MEDIUM,
            "The strict-transport-security header was not sent.",
            "A visitor's first request can be downgraded to unencrypted HTTP on a hostile network.",
            "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )
        return
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    if max_age < HSTS_MIN_SECONDS:
        finding(
            "HSTS lifetime is short",
            Severity.LOW,
            f"Strict-Transport-Security: {value}",
            "Browsers forget to force HTTPS soon after a visit.",
            "Set max-age to at least 15552000 (180 days), ideally 31536000.",
        )
    else:
        passed.append("HTTP Strict Transport Security (HSTS)")


def _check_http_redirect(final_url, http_check, finding, passed):
    if http_check is None:
        return
    if http_check.final_url and http_check.final_url.lower().startswith("https://"):
        passed.append("HTTP redirects to HTTPS")
    elif http_check.final_status is not None:
        finding(
            "HTTP version does not redirect to HTTPS",
            Severity.MEDIUM,
            f"http:// requests end at {http_check.final_url} (status {http_check.final_status}) instead of HTTPS.",
            "Visitors who type the address without https:// use an unencrypted connection.",
            "Redirect every HTTP request to the HTTPS address with a 301 redirect.",
        )


def _check_cookies(cookies, https, finding, passed):
    if not cookies:
        return
    weak = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        attributes = cookie.lower()
        missing = [
            flag for flag, present in (
                ("Secure", "; secure" in attributes or not https),
                ("HttpOnly", "httponly" in attributes),
                ("SameSite", "samesite" in attributes),
            ) if not present
        ]
        if missing:
            weak.append(f"{name} (missing {', '.join(missing)})")
    if weak:
        finding(
            "Cookies without protective flags",
            Severity.LOW,
            "; ".join(weak[:5]),
            "Cookies without these flags are easier to steal or misuse, for example in session hijacking.",
            "Set Secure, HttpOnly and SameSite on cookies, especially session cookies.",
        )
    else:
        passed.append("Cookie flags (Secure, HttpOnly, SameSite)")


def _check_version_disclosure(headers, finding, passed):
    disclosed = [
        f"{name}: {headers[name]}"
        for name in ("server", "x-powered-by", "x-aspnet-version")
        if name in headers and VERSION_PATTERN.search(headers[name])
    ]
    if disclosed:
        finding(
            "Server software version disclosed",
            Severity.LOW,
            "; ".join(disclosed),
            "Attackers can match the exact version against known vulnerabilities.",
            "Hide version numbers in Server and X-Powered-By headers, and keep the software updated.",
        )
    else:
        passed.append("No software versions disclosed in headers")


def _check_tls(tls, finding):
    if tls is None or not tls.completed:
        return
    if tls.details.get("legacy_tls_accepted") is True:
        finding(
            "Server accepts outdated TLS 1.0/1.1",
            Severity.MEDIUM,
            "A TLS 1.0/1.1 handshake succeeded.",
            "These protocol versions have known weaknesses and are disabled in modern browsers.",
            "Allow only TLS 1.2 and TLS 1.3.",
        )
