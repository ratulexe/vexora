require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const { TESTNET_RPC_URL, TESTNET_PRIVATE_KEY } = process.env;

module.exports = {
  solidity: "0.8.24",
  networks:
    TESTNET_RPC_URL && TESTNET_PRIVATE_KEY
      ? { testnet: { url: TESTNET_RPC_URL, accounts: [TESTNET_PRIVATE_KEY] } }
      : {},
};
