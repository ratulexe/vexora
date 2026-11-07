// Deploys ThreatReportRegistry, records the address and transaction in
// deployments/<network>.json, and copies the ABI to the backend and frontend.
//   npx hardhat run scripts/deploy.js --network localhost
//   npx hardhat run scripts/deploy.js --network sepolia
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying from ${deployer.address} on ${network.name}...`);

  const registry = await (await ethers.getContractFactory("ThreatReportRegistry")).deploy();
  const receipt = await registry.deploymentTransaction().wait();
  const address = await registry.getAddress();
  const { chainId } = await ethers.provider.getNetwork();

  const deployment = {
    network: network.name,
    chainId: Number(chainId),
    address,
    deploymentTransaction: receipt.hash,
    blockNumber: receipt.blockNumber,
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
  };
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(deploymentsDir, { recursive: true });
  fs.writeFileSync(path.join(deploymentsDir, `${network.name}.json`), JSON.stringify(deployment, null, 2) + "\n");

  const { abi } = await hre.artifacts.readArtifact("ThreatReportRegistry");
  const abiTargets = [
    path.join(__dirname, "..", "..", "backend", "app", "registry", "abi.json"),
    path.join(__dirname, "..", "..", "frontend", "src", "lib", "registry-abi.json"),
  ];
  for (const target of abiTargets) {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify(abi, null, 2) + "\n");
  }

  console.log(JSON.stringify(deployment, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
