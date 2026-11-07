// Dispute or validate a registered report, for demos and moderation.
//   ACTION=dispute  COMMITMENT=0x... REASON="false positive" npx hardhat run scripts/manage.js --network sepolia
//   ACTION=validate COMMITMENT=0x... npx hardhat run scripts/manage.js --network sepolia
//   ACTION=reject   COMMITMENT=0x... npx hardhat run scripts/manage.js --network sepolia
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");

async function main() {
  const { ACTION, COMMITMENT, REASON = "" } = process.env;
  if (!ACTION || !COMMITMENT) throw new Error("Set ACTION and COMMITMENT.");

  const deployment = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployments", `${network.name}.json`)));
  const registry = await ethers.getContractAt("ThreatReportRegistry", deployment.address);

  const tx =
    ACTION === "dispute"
      ? await registry.disputeReport(COMMITMENT, ethers.id(REASON))
      : ACTION === "validate" || ACTION === "reject"
        ? await registry.validateReport(COMMITMENT, ACTION === "validate")
        : null;
  if (!tx) throw new Error(`Unknown ACTION '${ACTION}'. Use dispute, validate or reject.`);

  const receipt = await tx.wait();
  const [, record] = await registry.verifyReport(COMMITMENT);
  console.log(`${ACTION} done in transaction ${receipt.hash}. Status is now ${record.status}.`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
