# Web3 threat registry

How Vexora shares threat reports with tamper-evident, verifiable history (Module 6). The contract is in `contracts/`, the server side in `backend/app/registry/`, and the verification page in `frontend/src/app/verify/`.

## How it works

1. **Report package** (`backend/app/registry/package.py`): when a user adds a Suspicious, High Risk or Confirmed Malicious report to the registry, the server builds a package containing only shareable data: the classification, finding titles and sources, the domains involved, the analysis time and a random 32-byte salt. It never contains message text, quoted evidence, full URLs, phone numbers or other personal details.
2. **Commitment**: the package is serialised as canonical JSON (keys sorted, no spaces, UTF-8) and hashed with keccak256. The salt stops anyone guessing a report's contents from its hash.
3. **On-chain record** (`contracts/contracts/ThreatReportRegistry.sol`): the server's testnet wallet calls `registerReport` with the commitment, the hash of the main domain, the classification and the report type. The contract records who registered it and when.
4. **Report file**: the user downloads the package with its commitment and transaction hash. This file is the only full copy of the report.
5. **Independent verification** (`/verify`): the browser recomputes the commitment from the file and reads the contract directly through a public RPC. It does not call the Vexora server, so anyone can check a report without trusting Vexora. Changing a single character produces a different hash, and the report is no longer found.

A registry record proves that a report has not changed since it was registered, and who registered it and when. **It does not prove that the report is true.**

## Contract features

| Feature | Function | Notes |
|---|---|---|
| Register | `registerReport` | Rejects empty, duplicate or invalid records |
| Verify | `verifyReport` | Returns the full record: reporter, time, status, classification, links to revisions, dispute count |
| Revise | `reviseReport` | Only the original reporter, once per report; the old version is kept and marked Superseded |
| Dispute | `disputeReport` | Anyone; the reason stays off-chain, only its hash is recorded |
| Validate | `validateReport` | Validators confirm or reject a report; the owner manages validators |
| Correlate | `indicatorReportCount` | How many reports name a domain hash; URL analysis uses this as a threat source |

Statuses: Active, Superseded, Disputed, Validated, Rejected. Every change emits an event, so the full history can be rebuilt from the chain.

## Correlation with URL analysis

When the registry is configured, URL analysis looks up the hash of the link's registered domain. If earlier reports name it, the report shows "Previously reported in the Vexora threat registry" as a Medium finding. This connects separate reports about the same infrastructure, even when the URLs differ. Community reports are integrity-protected but not independently verified, so this never makes a link Confirmed Malicious by itself.

## Safety

- **Only hashes go on-chain**; raw URLs, message text and personal data stay off-chain.
- **Testnet-only wallet**: the server pays gas from a wallet that holds only free testnet ETH. Its key is kept in environment variables, never in the repository.
- **Rate limit**: each visitor can register 5 reports per 10 minutes, to protect the wallet's testnet funds.
- **Limitations**: the server builds the package from the report the browser sends, so a registered report shows what was submitted, not proof that Vexora produced it. The registry is a shared history, not an authority.

## Run it locally

From `contracts/`:

```bash
npm install
npm run node
```

In a second terminal, still in `contracts/`:

```bash
npm run deploy:local
```

Then start the backend with these environment variables. The private key is Hardhat's public default test account, which only holds funds on your local chain:

```
REGISTRY_RPC_URL=http://127.0.0.1:8545
REGISTRY_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
REGISTRY_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

Set these in `frontend/.env.local`:

```
NEXT_PUBLIC_REGISTRY_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
NEXT_PUBLIC_REGISTRY_RPC_URL=http://127.0.0.1:8545
NEXT_PUBLIC_REGISTRY_NETWORK=local Hardhat chain
```

## Deploy to Sepolia

1. Create a testnet-only wallet with `npm run new-wallet` in `contracts/`. It saves the key to `contracts/.env`, which git ignores, and prints only the address.
2. Get free Sepolia ETH for that address from a faucet.
3. Deploy with `npm run deploy:sepolia`. This writes `contracts/deployments/sepolia.json` with the contract address, deployment transaction and block number. Commit that file as deployment evidence.
4. Set the backend environment on Render: `REGISTRY_RPC_URL`, `REGISTRY_CONTRACT_ADDRESS`, `REGISTRY_PRIVATE_KEY` (from `contracts/.env`) and `REGISTRY_EXPLORER_URL=https://sepolia.etherscan.io`.
5. Set the frontend environment on Vercel: `NEXT_PUBLIC_REGISTRY_ADDRESS`, `NEXT_PUBLIC_REGISTRY_RPC_URL`, `NEXT_PUBLIC_REGISTRY_EXPLORER_URL`, `NEXT_PUBLIC_REGISTRY_FROM_BLOCK` (the deployment block) and `NEXT_PUBLIC_REGISTRY_NETWORK=Sepolia testnet`. Then redeploy the frontend.

To dispute or validate a report for a demo:

```bash
ACTION=dispute COMMITMENT=0x... REASON="false positive" npx hardhat run scripts/manage.js --network sepolia
```

## Sepolia deployment

- Contract: [`0x5c886E470a08D0C30D6b1871989B3b6A9c5bca9C`](https://sepolia.etherscan.io/address/0x5c886E470a08D0C30D6b1871989B3b6A9c5bca9C)
- Deployment transaction: [`0x992b9d28fbf584420a04e25f170bf75a3c73deae6c666bd8c77f17c9a960c0eb`](https://sepolia.etherscan.io/tx/0x992b9d28fbf584420a04e25f170bf75a3c73deae6c666bd8c77f17c9a960c0eb), block 12083376
- Server wallet (owner and validator): `0xEB3162b9379457c64E0b734f62002EB55C50ab0B`
- Example registration: a Suspicious report for `paypa1-secure-login.com`, transaction [`0x513c60aeed7ca1d202bda214c027dd2e22674b0367cf514c8a7cd299f7d7f171`](https://sepolia.etherscan.io/tx/0x513c60aeed7ca1d202bda214c027dd2e22674b0367cf514c8a7cd299f7d7f171), block 12083380, commitment `0x5a278772e3e0e9be26a2da13131051020dd125e13f17d2ecda03e8402a999ddf`

## Test results

Run on 7 November 2026.

- **Contract**: 10 tests pass, covering registration, tamper detection, duplicates, revisions, disputes, validation and permissions.
- **Backend**: 13 registry tests pass, covering package contents, canonical JSON, salts, refusing Low Risk reports, the endpoint, rate limiting and chain failures.
- **Sepolia**: the deployed contract registered the example report above in about 27 seconds, and `indicatorReportCount` for the domain then returned 1.
- **End to end on a local chain**: a Suspicious link report was registered from the web page in block 2. The verification page recomputed the same commitment in the browser and showed it as unchanged. Changing "Suspicious" to "Low Risk" in the file made it not found. After a dispute, the page showed status Disputed. A different URL on the same domain then showed "Previously reported in the Vexora threat registry".
