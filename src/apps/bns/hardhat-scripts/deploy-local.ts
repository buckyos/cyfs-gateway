import hre from "hardhat";
import type { NetworkConnection } from "hardhat/types/network";

import {
  checkFacets,
  deployBns,
  readDeploymentNetwork,
} from "./deploy-common.js";

async function assertLocalRpc(connection: NetworkConnection): Promise<string> {
  if (connection.networkConfig.type !== "http") {
    throw new Error("Local deployment requires an HTTP JSON-RPC network");
  }

  const rpcUrl = await connection.networkConfig.url.getUrl();
  const hostname = new URL(rpcUrl).hostname.toLowerCase();
  if (hostname !== "localhost" && hostname !== "127.0.0.1") {
    throw new Error(
      `Refusing local deployment to non-local RPC host: ${hostname}`,
    );
  }
  return rpcUrl;
}

async function main(): Promise<void> {
  const connection = await hre.network.create();
  const rpcUrl = await assertLocalRpc(connection);

  console.error(`Local RPC: ${rpcUrl}`);
  checkFacets(true);

  const network = await readDeploymentNetwork(connection);
  const deployment = await deployBns(connection, network, console.error);

  // Match `forge create --json` so existing shell and Rust parsers can keep
  // reading the proxy address from `deployedTo`.
  console.log(
    JSON.stringify(
      {
        deployer: deployment.deployer,
        deployedTo: deployment.proxyAddress,
        transactionHash: deployment.proxyDeploymentTransaction.hash,
      },
      null,
      2,
    ),
  );
}

await main();
