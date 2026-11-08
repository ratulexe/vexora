# Vexora

Vexora investigates suspicious links and messages, explains the evidence, and records tamper-evident threat reports on-chain.

## Problem

Phishing sites, fraudulent payment links and scam messages can closely imitate trusted organisations. Existing tools tend to check these risks separately and often give a verdict without showing the evidence behind it.

## Solution

Anyone can submit a URL, domain, email or message. Vexora runs security checks, explains the findings in plain language, and gives a risk classification with its evidence, sources and limitations. Users can then register a cryptographic commitment to a threat report on-chain, so anyone can check that it has not been altered.

A blockchain record proves a report's integrity and history, not that the report is true. A valid TLS certificate, or the absence of known threats, is never treated as proof that a site is safe.

## Demo links and screenshot

- Live demo: TODO
- Demo video (3 minutes maximum): TODO
- Pitch deck: TODO
- Threat registry contract (Ethereum Sepolia testnet): [`0x5c886E470a08D0C30D6b1871989B3b6A9c5bca9C`](https://sepolia.etherscan.io/address/0x5c886E470a08D0C30D6b1871989B3b6A9c5bca9C)
  - Deployment transaction: [`0x992b9d28...60c0eb`](https://sepolia.etherscan.io/tx/0x992b9d28fbf584420a04e25f170bf75a3c73deae6c666bd8c77f17c9a960c0eb) (block 12083376)
  - Example report registration: [`0x513c60ae...7d7f171`](https://sepolia.etherscan.io/tx/0x513c60aeed7ca1d202bda214c027dd2e22674b0367cf514c8a7cd299f7d7f171), commitment `0x5a278772e3e0e9be26a2da13131051020dd125e13f17d2ecda03e8402a999ddf`
  - Details: [contracts/deployments/sepolia.json](contracts/deployments/sepolia.json)

TODO: add a screenshot.

## Tech stack

- Frontend: Next.js, TypeScript
- Backend: Python, FastAPI
- Blockchain: Solidity, Hardhat, Ethereum Sepolia testnet, web3.py, ethers.js
- Threat intelligence: OpenPhish community feed, with optional URLhaus and Google Safe Browsing
- Domain intelligence: RDAP (rdap.org) and Certificate Transparency logs (crt.sh)
- AI: Claude (`claude-haiku-5-5`) through the Anthropic Python SDK, for explanations only
- TODO: database

See [docs/url-analysis.md](docs/url-analysis.md), [docs/message-analysis.md](docs/message-analysis.md), [docs/correlation.md](docs/correlation.md) and [docs/web3-registry.md](docs/web3-registry.md) for the pipelines, safety measures and test results.

## Architecture

```
Browser (frontend/) --> FastAPI (backend/) --> URL, TLS and threat intelligence checks
                                           --> AI explanations
Browser (frontend/) --> ThreatReportRegistry contract (contracts/)
```

TODO: replace this with the final architecture and analysis pipeline.

## Setup and run steps

Copy each `.env.example` file to `.env` (`.env.local` for the frontend) and fill in your own values. Never commit real keys.

### Backend

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
pytest
```

The API runs at http://localhost:8000, with interactive docs at `/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The app runs at http://localhost:3000.

### Contracts

```bash
cd contracts
npm install
npm test
```

To run the registry on a local blockchain or deploy it to Sepolia, see [docs/web3-registry.md](docs/web3-registry.md).

## Disclosures

- Libraries: FastAPI, Pydantic, Uvicorn, HTTPX, idna, tldextract, cryptography, Anthropic Python SDK, web3.py, pytest, Next.js, React, ethers.js, Hardhat, Hardhat Toolbox
- Data sources: OpenPhish community feed, URLhaus, Google Safe Browsing, RDAP, crt.sh
- Templates: `create-next-app` for the frontend
- AI tools: Claude Code was used to generate the initial project skeleton and the URL analysis, message analysis and threat registry modules
- TODO: add every other library, API, template and AI tool you use

## Track

AI-Powered Web Threat Detection & Digital Trust Intelligence
