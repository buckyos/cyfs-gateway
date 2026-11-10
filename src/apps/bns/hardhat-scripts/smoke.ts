import { getAddress } from "ethers";
import hre from "hardhat";
import type { NetworkConnection } from "hardhat/types/network";

import { checkFacets, deployBns, readDeploymentNetwork } from "./deploy-common.js";
import { Smoke } from "./smoke-common.js";
import { testBns } from "./smoke-test.js";
import { testTime } from "./smoke-time.js";
import { testAdmin } from "./smoke-admin.js";

async function isLocalHardhat(connection: NetworkConnection): Promise<boolean> {
  if (connection.networkConfig.type === "edr-simulated") return true;
  if (connection.networkName !== "localhost") return false;
  const host = new URL(await connection.networkConfig.url.getUrl()).hostname;
  if (host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]") {
    throw new Error("The localhost smoke network must use a loopback Hardhat RPC endpoint");
  }
  const client = await connection.provider.request({ method: "web3_clientVersion", params: [] });
  if (typeof client !== "string" || !client.toLowerCase().includes("hardhat")) {
    throw new Error("The localhost smoke network requires hardhat node; use another network name for external contracts");
  }
  return true;
}

async function main(): Promise<void> {
  const connection = await hre.network.create();
  try {
    const local = await isLocalHardhat(connection);
    const deploy = local || connection.networkName === "anvil";
    let proxyAddress: string;
    if (deploy) {
      checkFacets();
      proxyAddress = (await deployBns(connection, await readDeploymentNetwork(connection))).proxyAddress;
    } else {
      const address = process.env.BNS_CONTRACT_ADDRESS?.trim();
      if (!address) throw new Error(`BNS_CONTRACT_ADDRESS is required for BNS smoke on network ${connection.networkName}. Provide the deployed BNS proxy address.`);
      proxyAddress = getAddress(address);
    }
    const network = await readDeploymentNetwork(connection);
    console.log(`Network: ${network.networkName} (chain ID ${network.chainId}); mode: ${local ? "local Hardhat" : "without time control"}`);
    const smoke = await Smoke.create(connection, proxyAddress);
    await testBns(smoke);
    if (local) {
      await testTime(smoke);
      await testAdmin(smoke);
    } else {
      console.log("[SKIP] time control: block mining, name/document expiry, controller/key validity boundaries");
      console.log("[SKIP] proxy administration: facet mutation, UUPS upgrade, ownership transfer/renunciation (local Hardhat only)");
    }
    smoke.report();
    console.log(`BNS smoke passed on ${connection.networkName}`);
  } finally {
    await connection.close();
  }
}

await main();
