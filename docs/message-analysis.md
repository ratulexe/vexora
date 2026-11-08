# Message analysis and AI

How Vexora analyses a pasted message or email (Module 3), and how AI is used. The code is in `backend/app/message_analysis/` and `backend/app/ai.py`.

## Pipeline

1. **Extract** (`extract.py`): links (including defanged and bare domains), email addresses, UPI IDs, Indian phone numbers, amounts and crypto wallet addresses.
2. **Rules** (`rules.py`): fixed patterns for credential requests, remote-access apps, arrest threats, upfront fees, account threats, KYC updates, prize lures, task-based jobs, investment scams, urgency and generic greetings. Each finding quotes the text that triggered it. Warnings such as "Do not share your OTP" are not flagged.
3. **Links** (`analyzer.py`): up to 3 links are checked with the full URL analysis. A message that names an organisation but links to a domain that organisation doesn't own is flagged.
4. **Classify**: the same fixed rules as URL analysis. A confirmed malicious link makes the message Confirmed Malicious.
5. **AI explanation** (`ai.py`): Claude writes a plain-language summary and may point out extra tactics.

## Language versus evidence

Every report states its `evidence_basis`: verified by threat intelligence, technical and language checks, language patterns only, or no warning signs found. Urgency alone is only Low severity, so it cannot make a message look dangerous by itself. When a result rests on wording only, the report says it is not verified proof of fraud.

## How AI is used safely

- **The AI never sets the risk level.** Fixed rules decide it. AI-found tactics are added only as Low severity findings.
- **Grounding:** every AI tactic must quote the message exactly. Quotes that do not appear in the message are discarded.
- **Prompt injection:** the message is sent inside `<untrusted_message>` tags, with any such tags in the text removed, and the instructions tell the model to ignore instructions inside it. Output is constrained to a JSON schema.
- **Privacy:** phone numbers, emails, UPI IDs, wallet addresses, PAN, long numbers (such as OTPs and account numbers) and link paths are redacted before anything is sent, including inside the findings.
- **Failure handling:** if the key is missing, the request fails or the model declines, the report is still returned, with a limitation saying the AI explanation is unavailable.

Model: `claude-haiku-5-5` at low effort, with structured JSON output. Haiku was chosen to keep costs to a fraction of a cent per analysis. Set `ANTHROPIC_API_KEY` to enable it.

## Test results

Run on 7 November 2026 with live link checks and no AI key.

| Message | Result | Evidence basis |
|---|---|---|
| SBI account blocked, KYC link to `sbi-kyc-update.in`, "Share the OTP" | High Risk | Technical and language checks |
| KBC lottery win, registration fee to a UPI ID | Suspicious | Language patterns only |
| Part-time job: like YouTube videos, earn Rs 3000 daily | Suspicious | Language patterns only |
| CBI money laundering case, install AnyDesk, digital arrest | High Risk | Language patterns only |
| Genuine HDFC OTP message: "Do not share it with anyone" | Low Risk | No warning signs found |
| Genuine meeting message with a GitHub link | Low Risk | No warning signs found |
| "URGENT: please reply by today" (genuine) | Low Risk | No warning signs found |

Automated tests: `backend/tests/test_messages.py` covers scam and genuine messages, extraction, redaction, brand mismatch, evidence basis, and the AI layer with a fake Claude client (grounding, prompt injection, redaction, refusals and a missing key).

## QR code investigation

QR codes are added on the **QR code** tab: upload an image, take a photo on a phone, paste a screenshot, or try a built-in sample. The image is decoded **in the browser** with jsQR and never uploaded. Only the decoded text is sent to `POST /analyze/qr`, which is handled by `backend/app/qr_analysis.py`:

| QR content | What Vexora does |
|---|---|
| Link | The full link analysis |
| UPI payment (`upi://pay?...`) | Payment checks, below |
| Wi-Fi network | Shows the network name only. The password is stripped in the browser and never stored, analysed or sent to the AI |
| Anything else | The message analysis |

UPI payment checks start from one fact: **scanning a UPI QR code can only send money, never receive it.** An ordinary shop code is Low Risk. Warnings come from scam signals:

| Signal | Severity |
|---|---|
| The name or note promises money (refund, prize, cashback, KYC, reward) | High |
| The payee name impersonates a brand (for example SBI) on a UPI ID that is not theirs | High |
| The payee name claims a generic authority (a bank, customer care, police) | Medium |
| Missing or malformed UPI ID | Medium |
| Pre-filled amount | Low |
| Scam patterns in the payment note (the message rules) | As in the rules |

The UPI ID is also fingerprinted for correlation, so a QR code that pays the same UPI ID as an earlier scam message is linked to it.

Tests in `backend/tests/test_qr.py` cover content types, the refund scam (High Risk), an ordinary shop (Low Risk), a brand using its own UPI ID (Low Risk), a generic authority name (Suspicious), Wi-Fi passwords never returned, links routed to link analysis, and a QR code linked to an earlier scam message by UPI ID. In the browser, the built-in "Fake refund UPI" sample decoded correctly and came back High Risk.
