# Threat correlation

How Vexora connects separate reports that belong to the same scam campaign (Module 4). The code is in `backend/app/correlation.py`.

## What is remembered

When a link or message is classified Suspicious, High Risk or Confirmed Malicious, Vexora keeps a fingerprint of it for 7 days:

| Fingerprint | From | Stored as |
|---|---|---|
| Registered domains | Links, and links inside messages | Plain text (public infrastructure) |
| Redirect destinations | The final site a link leads to | Plain text |
| Server addresses | IPs the link resolved to | Plain text |
| Organisations impersonated or named | Brand findings and names in messages | Plain text |
| Phone numbers, UPI IDs, email addresses | Messages | Keyed hashes only |
| Wording | Messages, after redaction, as 4-word phrases | Keyed hashes only |

Raw messages and contact details are never stored. The hash key is random and exists only in the server's memory, so the hashes cannot be reversed by guessing. Low Risk reports are not recorded. Everything is cleared when the server restarts; the on-chain registry is the long-term record.

## How reports are linked

Connections come from exact matching only. The AI may describe them in its summary, but it never decides them.

| Connection | Strength |
|---|---|
| Same registered domain | Strong |
| Lead to the same site (for example, two short links redirecting to one phishing page) | Strong |
| Same phone number, UPI ID or email address | Strong |
| Similar wording: at least 50% of 4-word phrases shared, for example the same template with a different phone number | Strong |
| Same server address | Weak, because it can be shared hosting or a CDN |
| Same organisation impersonated or named | Weak |

A report with strong links gets the Medium finding **Linked to N earlier suspicious report(s)**. If it was Low Risk, it becomes Suspicious, because reusing a known scammer's phone number or payment destination is evidence on its own. Weak links are shown but add no finding. Each report shows its links in a **Related reports** section, and the AI explanation can mention them.

The on-chain registry adds a second, persistent connection: a domain named in earlier registered reports shows **Previously reported in the Vexora threat registry** (see [web3-registry.md](web3-registry.md)).

## Test results

`backend/tests/test_correlation.py` (9 tests) covers:
- two differently worded scams linked by the same UPI ID
- template messages linked by wording
- a plain-looking message raised to Suspicious for reusing a scammer's phone number
- short links that redirect to the same site
- brand-only matches staying weak
- benign messages not being recorded
- a report not linking to itself
- expiry
- raw contact details and text never appearing in memory

Checked in the web page on 7 November 2026: a lottery scam was submitted, then a differently worded parcel scam reusing its UPI ID. The second showed **Linked to 1 earlier suspicious report(s)** and a Related reports entry, "Strong link: Same UPI ID", without revealing the UPI ID.
