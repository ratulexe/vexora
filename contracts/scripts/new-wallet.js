// Creates a fresh testnet-only wallet and saves its private key to contracts/.env
// (which git ignores). Only the public address is printed.
const fs = require("fs");
const path = require("path");
const { Wallet } = require("ethers");

const envPath = path.join(__dirname, "..", ".env");
const existing = fs.existsSync(envPath) ? fs.readFileSync(envPath, "utf8") : "";
if (/^DEPLOYER_PRIVATE_KEY=0x[0-9a-fA-F]{64}/m.test(existing)) {
  const key = existing.match(/^DEPLOYER_PRIVATE_KEY=(0x[0-9a-fA-F]{64})/m)[1];
  console.log(`A wallet already exists in .env. Address: ${new Wallet(key).address}`);
  process.exit(0);
}

const wallet = Wallet.createRandom();
const lines = existing.split(/\r?\n/).filter((line) => line && !line.startsWith("DEPLOYER_PRIVATE_KEY="));
lines.push(`DEPLOYER_PRIVATE_KEY=${wallet.privateKey}`);
if (!lines.some((line) => line.startsWith("SEPOLIA_RPC_URL="))) {
  lines.push("SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com");
}
fs.writeFileSync(envPath, lines.join("\n") + "\n");
console.log(`New testnet wallet saved to contracts/.env. Address: ${wallet.address}`);
