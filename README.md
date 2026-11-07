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
- Contract address and transaction: TODO

TODO: add a screenshot.

## Tech stack

- Frontend: Next.js, TypeScript
- Backend: Python, FastAPI
- Blockchain: Solidity, Hardhat, EVM testnet
- TODO: AI provider, threat intelligence sources and database

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

## Disclosures

- Libraries: FastAPI, Pydantic, Uvicorn, pytest, Next.js, React, Hardhat, Hardhat Toolbox
- Templates: `create-next-app` for the frontend
- AI tools: Claude Code was used to generate the initial project skeleton
- TODO: add every other library, API, template and AI tool you use

## Track

AI-Powered Web Threat Detection & Digital Trust Intelligence
