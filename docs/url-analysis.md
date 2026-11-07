# URL analysis

How Vexora investigates a submitted link (Modules 1 and 2 of the problem statement). The code is in `backend/app/url_analysis/`.

## Pipeline

1. **Normalise** (`normalize.py`): undo defanging (`hxxp`, `[.]`), add a missing scheme, allow only http and https, convert internationalised hosts to punycode, remove credentials and fragments, and find the registered domain using the bundled public suffix list.
2. **Domain checks** (`domain_checks.py`, no network): brand impersonation, typosquatting, look-alike characters and mixed alphabets (homographs), the `@` trick, raw or obfuscated IP addresses, link shorteners, embedded redirect parameters and unusual structure.
3. **Threat intelligence** (`threat_intel.py`): OpenPhish community feed (no key), plus URLhaus and Google Safe Browsing when their keys are set. If a source confirms the URL, Vexora does **not** contact the site.
4. **Redirects** (`safe_fetch.py`, `analyzer.py`): follows up to 5 redirects, recording each hop, cross-domain redirects and HTTPS-to-HTTP downgrades.
5. **TLS** (`tls_check.py`): verifies the certificate, then reads its names, issuer, dates, key and signature algorithm, and checks the issuer against a documented list of distrusted CAs (`distrusted_cas.py`). Trust incidents are labelled separately from configuration errors.
6. **Domain intelligence** (`domain_intel.py`): registration age from RDAP and unexpired certificates from Certificate Transparency logs (crt.sh).
7. **Classify** (`classify.py`): fixed rules, so the AI can explain the result but never set it.

| Classification | Rule |
|---|---|
| Confirmed Malicious | A threat intelligence source lists the URL |
| High Risk | 2 or more High indicators, or 1 High and 2 or more Medium |
| Suspicious | At least 1 High or Medium indicator |
| Inconclusive | No warning signs, but the site could not be reached or no threat source was available |
| Low Risk | No warning signs and all core checks ran. This never means "safe". |

## Safety

- **SSRF protection:** every hop is checked before connecting. Only http and https on ports 80 and 443 are allowed, and every resolved address must be public, so loopback, private, link-local, cloud metadata and IPv4-mapped IPv6 addresses are all refused. Requests connect to the IP that was checked, so DNS cannot switch to an internal address mid-request.
- **No content execution:** Vexora never reads page bodies, runs scripts or downloads files. Requests have a 5-second timeout and a 15-second budget for the whole redirect chain.
- **Privacy:** submitted URLs are sent to the configured threat intelligence services and the domain to RDAP and crt.sh. Nothing else leaves the server.

## Limitations

- A valid certificate or a clean result does not mean a site is safe.
- Page content, JavaScript and meta-refresh redirects are not analysed.
- Certificate revocation (OCSP/CRL) is not checked.
- Distrusted CAs are matched by issuer name, not fingerprint.
- Brand checks only cover the brands listed in `domain_checks.py`.

## Test results

Run on 7 November 2026 against live sites, with OpenPhish as the only threat source (no URLhaus or Safe Browsing keys).

| Type | Input | Result | Main findings |
|---|---|---|---|
| Benign | `https://google.com` | Low Risk | Valid, trusted certificate only |
| Benign | `https://github.com` | Low Risk | Valid, trusted certificate only |
| Benign | `https://www.wikipedia.org` | Low Risk | Valid, trusted certificate only |
| Suspicious | `https://expired.badssl.com` | Suspicious | High: certificate has expired |
| Suspicious | `https://self-signed.badssl.com` | Suspicious | High: self-signed certificate |
| Suspicious | `https://wrong.host.badssl.com` | Suspicious | High: certificate does not match the domain |
| Suspicious | `https://paypa1-secure-login.com/verify` | Suspicious | High: impersonates PayPal with look-alike characters |
| Suspicious | `https://аpple.com` (Cyrillic "а") | High Risk | High: mixed alphabets (homograph); High: impersonates Apple |
| Suspicious | `http://127.0.0.1/admin` | Suspicious | Medium: internal address, blocked without connecting |
| Malicious | A URL from the OpenPhish feed | Confirmed Malicious | Critical: listed as active phishing; site not contacted |

Automated tests: `cd backend && pytest` runs 64 offline tests covering normalisation, phishing patterns, benign look-alikes (to catch false positives), SSRF blocking, certificate parsing, distrusted-CA dates, classification rules and the API.
