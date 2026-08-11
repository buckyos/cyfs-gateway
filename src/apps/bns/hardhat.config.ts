import hardhatUpgrades from "@openzeppelin/hardhat-upgrades";
import { configVariable, defineConfig } from "hardhat/config";

const privateKey = process.env.BNS_ANVIL_PRIVATE_KEY;

export default defineConfig({
  plugins: [hardhatUpgrades],
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 20,
      },
      viaIR: true,
      evmVersion: "paris",
    },
  },
  paths: {
    sources: "./src",
    tests: {
      solidity: "./test",
    },
    artifacts: "./artifacts",
    cache: "./cache/hardhat",
  },
  test: {
    solidity: {
      isolate: true,
      fuzz: {
        runs: 256,
      },
      invariant: {
        runs: 256,
        depth: 15,
      },
    },
  },
  networks: {
    anvil: {
      type: "http",
      chainType: "l1",
      url: process.env.BNS_ANVIL_RPC_URL ?? "http://127.0.0.1:8545",
      accounts: privateKey ? [privateKey] : "remote",
    },
    opMainnet: {
      type: "http",
      chainType: "op",
      chainId: 10,
      url: configVariable("BNS_OP_MAINNET_RPC_URL"),
      accounts: [configVariable("BNS_DEPLOYER_PRIVATE_KEY")],
    },
  },
});
