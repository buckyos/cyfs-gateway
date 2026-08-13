import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { upgrades } from "@openzeppelin/hardhat-upgrades";
import { getAddress } from "ethers";
import hre from "hardhat";
import type { NetworkConnection } from "hardhat/types/network";

export const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const contractDirectory = path.resolve(scriptDirectory, "..");

const facetFunctionNames = JSON.parse(
  await readFile(path.join(scriptDirectory, "facet-manifest.json"), "utf8"),
) as Record<string, readonly string[]>;

const maxRuntimeBytecodeSize = 24_576;

export interface DeploymentNetwork {
  networkName: string;
  chainId: number;
}

export interface FacetDeployment {
  contractName: string;
  address: string;
  bytecodeSize: number;
  selectors: string[];
  deploymentTransaction: {
    hash: string;
    blockNumber: string;
  };
}

export interface BnsDeployment extends DeploymentNetwork {
  deployer: string;
  upgradeAdmin: string;
  proxyAddress: string;
  implementationAddress: string;
  implementationBytecodeSize: number;
  facets: FacetDeployment[];
  facetConfigurationTransaction: {
    hash: string;
    blockNumber: string;
  };
  proxyDeploymentTransaction: {
    hash: string;
    blockNumber: string;
  };
}

type DeploymentLogger = (message: string) => void;

export function checkFacets(outputToStderr = false): void {
  execFileSync(process.execPath, [path.join(scriptDirectory, "check-facets.mjs")], {
    cwd: contractDirectory,
    stdio: outputToStderr
      ? ["ignore", process.stderr, process.stderr]
      : "inherit",
  });
}

export async function readDeploymentNetwork(
  connection: NetworkConnection,
): Promise<DeploymentNetwork> {
  const network = await connection.ethers.provider.getNetwork();
  if (network.chainId > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`Chain ID is too large to record safely: ${network.chainId}`);
  }

  return {
    networkName: connection.networkName,
    chainId: Number(network.chainId),
  };
}

export async function deployBns(
  connection: NetworkConnection,
  network: DeploymentNetwork,
  log: DeploymentLogger = console.log,
): Promise<BnsDeployment> {
  const { ethers } = connection;
  const upgradesApi = await upgrades(hre, connection);
  const [deployerSigner] = await ethers.getSigners();
  if (deployerSigner === undefined) {
    throw new Error(`No deployment account configured for network ${network.networkName}`);
  }
  const deployer = getAddress(await deployerSigner.getAddress());
  const upgradeAdmin = deployer;

  log(`Network: ${network.networkName} (chain ID ${network.chainId})`);
  log(`Deploying from: ${deployer}`);
  log(`Owner / upgrade admin: ${upgradeAdmin}`);

  const facets: FacetDeployment[] = [];
  const assignedSelectors = new Set<string>();
  for (const [contractName, functionNames] of Object.entries(
    facetFunctionNames,
  )) {
    const factory = await ethers.getContractFactory(contractName, deployerSigner);
    const facet = await factory.deploy();
    await facet.waitForDeployment();
    const deploymentTransaction = facet.deploymentTransaction();
    if (deploymentTransaction === null) {
      throw new Error(`${contractName} deployment transaction is unavailable`);
    }
    const receipt = await deploymentTransaction.wait();
    if (receipt === null || receipt.status !== 1) {
      throw new Error(
        `${contractName} deployment reverted: ${deploymentTransaction.hash}`,
      );
    }
    const address = getAddress(await facet.getAddress());
    const code = await ethers.provider.getCode(address);
    const bytecodeSize = (code.length - 2) / 2;
    if (bytecodeSize > maxRuntimeBytecodeSize) {
      throw new Error(
        `${contractName} runtime is ${bytecodeSize} bytes, exceeding ${maxRuntimeBytecodeSize}`,
      );
    }
    const selectors = functionNames.map((functionName) => {
      const fragment = facet.interface.getFunction(functionName);
      if (fragment === null) {
        throw new Error(`${contractName} has no function named ${functionName}`);
      }
      const selector = fragment.selector;
      if (assignedSelectors.has(selector)) {
        throw new Error(`Duplicate facet selector ${selector} (${functionName})`);
      }
      assignedSelectors.add(selector);
      return selector;
    });
    facets.push({
      contractName,
      address,
      bytecodeSize,
      selectors,
      deploymentTransaction: {
        hash: deploymentTransaction.hash,
        blockNumber: receipt.blockNumber.toString(),
      },
    });
    log(`${contractName}: ${address} (${bytecodeSize} bytes)`);
  }

  const Bns = await ethers.getContractFactory("Bns", deployerSigner);
  const proxy = await upgradesApi.deployProxy(Bns, [upgradeAdmin], {
    kind: "uups",
  });
  await proxy.waitForDeployment();

  const proxyDeploymentTransaction = proxy.deploymentTransaction();
  if (proxyDeploymentTransaction === null) {
    throw new Error("The proxy deployment transaction is unavailable");
  }
  const proxyReceipt = await proxyDeploymentTransaction.wait();
  if (proxyReceipt === null || proxyReceipt.status !== 1) {
    throw new Error(
      `BNS proxy deployment reverted: ${proxyDeploymentTransaction.hash}`,
    );
  }

  const proxyAddress = getAddress(await proxy.getAddress());
  const facetConfigurationTransaction = await proxy.addFacets(
    facets.map((facet) => ({
      facet: facet.address,
      selectors: facet.selectors,
    })),
  );
  const facetConfigurationReceipt = await facetConfigurationTransaction.wait();
  if (
    facetConfigurationReceipt === null ||
    facetConfigurationReceipt.status !== 1
  ) {
    throw new Error(
      `BNS facet configuration reverted: ${facetConfigurationTransaction.hash}`,
    );
  }
  for (const facet of facets) {
    for (const selector of facet.selectors) {
      const configuredFacet = getAddress(await proxy.facetForSelector(selector));
      if (configuredFacet !== facet.address) {
        throw new Error(
          `Facet selector ${selector} mismatch: ${configuredFacet} != ${facet.address}`,
        );
      }
    }
  }
  const implementationAddress = getAddress(
    await upgradesApi.erc1967.getImplementationAddress(proxyAddress),
  );
  const configuredUpgradeAdmin = getAddress(await proxy.owner());
  if (configuredUpgradeAdmin !== upgradeAdmin) {
    throw new Error(
      `Proxy upgrade admin mismatch: ${configuredUpgradeAdmin} != ${upgradeAdmin}`,
    );
  }

  const implementationCode = await ethers.provider.getCode(implementationAddress);
  const implementationBytecodeSize = (implementationCode.length - 2) / 2;

  return {
    ...network,
    deployer,
    upgradeAdmin,
    proxyAddress,
    implementationAddress,
    implementationBytecodeSize,
    facets,
    facetConfigurationTransaction: {
      hash: facetConfigurationTransaction.hash,
      blockNumber: facetConfigurationReceipt.blockNumber.toString(),
    },
    proxyDeploymentTransaction: {
      hash: proxyDeploymentTransaction.hash,
      blockNumber: proxyReceipt.blockNumber.toString(),
    },
  };
}
