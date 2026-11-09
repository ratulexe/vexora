# Testing report

All automated suites and live test cases for Vexora, run on 7 November 2026. The problem statement requires at least three suspicious and three benign test cases; this report covers links, messages, TLS, website security, correlation and the blockchain registry.

## Automated tests

| Suite | Command | Result |
|---|---|---|
| Backend (offline; no network, Claude or blockchain needed) | `cd backend && pytest` | 162 passed |
| Smart contract | `cd contracts && npm test` | 10 passed |
| Frontend | `cd frontend && npm run lint && npm run build` | Lint clean, build succeeds |

Backend coverage by file:

| File | Covers |
|---|---|
| `test_url_checks.py` | URL normalisation; phishing patterns; benign look-alikes (false positives); SSRF blocking including NAT64; certificate parsing; distrusted-CA dates; classification rules |
| `test_api.py` | Link and message endpoints end to end with faked network checks |
| `test_messages.py` | Scam rules; genuine messages not flagged; extraction; redaction; brand mismatch; evidence basis; the AI layer with a fake Claude client (grounding, prompt injection, redaction, refusals, missing key) |
| `test_security_assessment.py` | Website security findings and certificate verdicts |
| `test_correlation.py` | Linking by UPI ID, wording, phone number and redirect destination; weak links; expiry; no raw data stored |
| `test_cache.py` | Expiry, copies, size limits, re-check, what is and is not cached, messages never stored |
| `test_rate_limit.py` | Sliding windows, visitor identification, per-visitor limits, shared AI budget |
| `test_qr.py` | QR content types; UPI refund scam, shop, brand and authority codes; Wi-Fi password privacy; routing; correlation by UPI ID |
| `test_registry.py` | Report packages, canonical JSON, salts, refusing Low Risk reports, the endpoint, rate limits, chain failures |

## Benign test cases

| Input | Expected | Observed |
|---|---|---|
| `https://google.com` | Low Risk | Low Risk; certificate Valid |
| `https://github.com` | Low Risk | Low Risk; certificate Valid; 1 Low website-security finding (a cookie without HttpOnly) |
| `https://www.wikipedia.org` | Low Risk | Low Risk; certificate Valid |
| `https://example.com` | Low Risk | Low Risk; certificate Valid; 7 configuration findings that do not change the risk level |
| Genuine HDFC OTP message: "Do not share it with anyone" | Low Risk | Low Risk; no rules triggered |
| Genuine meeting message with a GitHub link | Low Risk | Low Risk; no warning signs found |
| "URGENT: please reply by today, the venue booking closes tonight." | Low Risk | Low Risk; urgency alone is only Low severity |

## Popular sites (false-positive sweep)

39 well-known sites were checked on 9 November 2026 the way the live server connects (IPv4 only), four times in a row. All 39 were Low Risk every time:

facebook.com, instagram.com, whatsapp.com, google.com, youtube.com, amazon.in, flipkart.com, wikipedia.org, x.com, twitter.com, linkedin.com, microsoft.com, apple.com, netflix.com, reddit.com, yahoo.com, bing.com, onlinesbi.sbi, sbi.co.in, hdfcbank.com, icicibank.com, axisbank.com, kotak.com, paytm.com, phonepe.com, incometax.gov.in, uidai.gov.in, india.gov.in, irctc.co.in, zomato.com, swiggy.com, myntra.com, openai.com, anthropic.com, cloudflare.com, github.com, stackoverflow.com, bbc.com, nytimes.com.

Before these fixes, facebook.com was Inconclusive on the live site and the first sweep found 11 more wrong results. Each cause was fixed:

| Cause | Sites affected | Fix |
|---|---|---|
| IPv6 address tried first; the server has no IPv6 | facebook.com, instagram.com | IPv4 first, then fall back to other addresses |
| `.bank.in` (RBI's restricted bank domain) not in the suffix list | onlinesbi.sbi (High Risk) | `.bank.in` and `.fin.in` added as suffixes; official `.bank.in` domains added |
| Redirect to another domain rated Medium | twitter.com, hdfcbank.com, icicibank.com, axisbank.com | Now Low; the destination is checked separately |
| Any issuer named "Entrust" treated as distrusted | sbi.co.in | Only Entrust's own roots; Entrust certificates under Sectigo's root are trusted |
| Bot protection stalls non-browser clients | zomato.com, myntra.com | Browser user agent and headers |
| Site answers, then a redirect within its own domain stalls | irctc.co.in, kotak.com | Counted as reached; the stall is listed as a limitation |
| Domain has no address without `www.` | incometax.gov.in | `www.` tried, and the report says so |

A site that is really down, or blocks every automated check, is still Inconclusive. That is deliberate: Vexora does not call a site Low Risk without evidence.

## Suspicious test cases

| Input | Expected | Observed |
|---|---|---|
| `https://expired.badssl.com` | Flag expired certificate | Suspicious: certificate has expired |
| `https://self-signed.badssl.com` | Flag untrusted certificate | Suspicious: self-signed certificate |
| `https://wrong.host.badssl.com` | Flag name mismatch | Suspicious: certificate does not match the domain |
| `https://paypa1-secure-login.com/verify` | Flag impersonation | Suspicious: impersonates PayPal with look-alike characters |
| `https://аpple.com` (Cyrillic "а") | Flag homograph | High Risk: mixed alphabets and Apple impersonation |
| `http://127.0.0.1/admin` | Block internal address | Blocked without connecting |
| A URL from the OpenPhish feed | Confirmed Malicious | Confirmed Malicious; the site was never contacted |
| SBI "account blocked", KYC link to `sbi-kyc-update.in`, "Share the OTP" | High Risk | High Risk; technical and language evidence |
| KBC lottery, registration fee to a UPI ID | Suspicious | Suspicious; AI explanation says it rests on wording only |
| Part-time job: like YouTube videos, earn Rs 3000 daily | Suspicious | Suspicious |
| CBI money laundering case, install AnyDesk, digital arrest | High Risk | High Risk |

## Correlation

| Steps | Observed |
|---|---|
| Lottery scam, then a differently worded parcel scam with the same UPI ID | Second report: "Linked to 1 earlier suspicious report(s)"; "Strong link: Same UPI ID" (UPI ID not shown) |
| Same domain checked again on another path, after a registry submission | "Previously reported in the Vexora threat registry" |

## Blockchain registry

| Steps | Observed |
|---|---|
| Deploy to Sepolia | Contract `0x5c886E470a08D0C30D6b1871989B3b6A9c5bca9C`, block 12083376 |
| Register a Suspicious link report from the live site | Registered in block 12083430 (transaction status 1) |
| Verify the downloaded report file on `/verify` (local chain) | "Verified: this report is unchanged" |
| Change "Suspicious" to "Low Risk" in the file and verify again | "Not found on-chain" |
| Dispute the report with `scripts/manage.js` (local chain) | `/verify` shows status Disputed, 1 dispute |

## Safety checks

| Check | Observed |
|---|---|
| Internal addresses (`127.0.0.1`, `169.254.169.254`, `localhost`, `::1`, NAT64-wrapped internal addresses) | All blocked before connecting |
| Prompt injection: a message that closes the untrusted-data tag and says "Ignore previous instructions" | Tag stripped; classification unchanged; AI tactics without real quotes discarded |
| Personal data sent to the AI | Phone numbers, UPI IDs, OTPs, PAN, emails and link paths redacted, including inside findings |
| 21 message checks from one visitor in 10 minutes | 20 accepted, the 21st refused with a clear message |
| Repeat check of the same link | 0.00 seconds instead of 6.7, marked as a saved result |

## Known limitations

- Certificate revocation (OCSP/CRL) is not checked.
- Page content and JavaScript are not analysed, so mixed content and JavaScript redirects are not detected.
- Website security checks are passive only; hidden files and endpoints are not probed.
- The correlation store and caches are in memory, so they reset when the server restarts.
- Brand impersonation checks cover the brands listed in `domain_checks.py`.
- Some live results depend on the network: `badssl.com` and `neverssl.com` occasionally dropped connections during testing, which shows as an incomplete check rather than a wrong result.
