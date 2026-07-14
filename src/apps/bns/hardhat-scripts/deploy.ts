import { execFileSync } from "node:child_process";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { upgrades } from "@openzeppelin/hardhat-upgrades";
import { getAddress } from "ethers";
import hre from "hardhat";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const contractDirectory = path.resolve(scriptDirectory, "..");

const facetFunctionNames = JSON.parse(
  await readFile(path.join(scriptDirectory, "facet-manifest.json"), "utf8"),
) as Record<string, readonly string[]>;

const maxRuntimeBytecodeSize = 24_576;

function git(repoRoot: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function toRepoPath(repoRoot: string, absolutePath: string): string {
  return path.relative(repoRoot, absolutePath).split(path.sep).join("/");
}

function assertDeploymentInputsCommitted(repoRoot: string): string {
  const deploymentInputs = [
    path.join(contractDirectory, "src"),
    path.join(contractDirectory, "hardhat.config.ts"),
    path.join(contractDirectory, "package.json"),
    path.join(contractDirectory, "package-lock.json"),
    fileURLToPath(import.meta.url),
    path.join(scriptDirectory, "check-facets.mjs"),
    path.join(scriptDirectory, "facet-manifest.json"),
  ].map((input) => toRepoPath(repoRoot, input));

  try {
    git(repoRoot, ["ls-files", "--error-unmatch", "--", ...deploymentInputs]);
  } catch {
    throw new Error(
      "All contract sources and deployment inputs must be tracked by Git before deployment.",
    );
  }

  const status = git(repoRoot, [
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
    "--",
    ...deploymentInputs,
  ]);
  if (status !== "") {
    throw new Error(
      `Deployment inputs must be committed before deployment:\n${status}`,
    );
  }

  return git(repoRoot, ["rev-parse", "HEAD"]);
}

function deploymentSlug(networkName: string, chainId: number): string {
  const slug = networkName
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[._-]+|[._-]+$/g, "")
    .toLowerCase();
  return slug === "" ? `chain-${chainId}` : slug;
}

async function assertOutputDoesNotExist(outputPath: string): Promise<void> {
  try {
    await stat(outputPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }

  throw new Error(
    `Deployment record already exists: ${outputPath}. Refusing to overwrite it.`,
  );
}

async function main(): Promise<void> {
  const repoRoot = git(contractDirectory, ["rev-parse", "--show-toplevel"]);
  const commit = assertDeploymentInputsCommitted(repoRoot);
  execFileSync(process.execPath, [path.join(scriptDirectory, "check-facets.mjs")], {
    cwd: contractDirectory,
    stdio: "inherit",
  });

  const connection = await hre.network.create();
  const { ethers } = connection;
  const upgradesApi = await upgrades(hre, connection);
  const network = await ethers.provider.getNetwork();
  if (network.chainId > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`Chain ID is too large to record safely: ${network.chainId}`);
  }

  const networkName = connection.networkName;
  const chainId = Number(network.chainId);

  const outputPath = path.join(
    contractDirectory,
    "deployments",
    `${deploymentSlug(networkName, chainId)}.json`,
  );
  await assertOutputDoesNotExist(outputPath);

  const [deployerSigner] = await ethers.getSigners();
  if (deployerSigner === undefined) {
    throw new Error(`No deployment account configured for network ${networkName}`);
  }
  const deployer = getAddress(await deployerSigner.getAddress());
  const upgradeAdmin = deployer;

  console.log(`Network: ${networkName} (chain ID ${chainId})`);
  console.log(`Deploying from: ${deployer}`);
  console.log(`Owner / upgrade admin: ${upgradeAdmin}`);
  console.log(`Source commit: ${commit}`);

  const facets = [];
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
      throw new Error(`${contractName} deployment reverted: ${deploymentTransaction.hash}`);
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
    console.log(`${contractName}: ${address} (${bytecodeSize} bytes)`);
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
    throw new Error(`BNS proxy deployment reverted: ${proxyDeploymentTransaction.hash}`);
  }

  const proxyAddress = getAddress(await proxy.getAddress());
  const facetConfigurationTransaction = await proxy.addFacets(
    facets.map((facet) => ({
      facet: facet.address,
      selectors: facet.selectors,
    })),
  );
  const facetConfigurationReceipt = await facetConfigurationTransaction.wait();
  if (facetConfigurationReceipt === null || facetConfigurationReceipt.status !== 1) {
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
  const record = {
    schemaVersion: 2,
    network: networkName,
    chainId,
    deployedAt: new Date().toISOString(),
    deploymentCommitHash: commit,
    proxyType: "uups",
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

  await mkdir(path.dirname(outputPath), { recursive: true });
  const temporaryOutputPath = `${outputPath}.tmp`;
  await writeFile(temporaryOutputPath, `${JSON.stringify(record, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
  await rename(temporaryOutputPath, outputPath);

  console.log("BNS UUPS deployment completed");
  console.log(`Proxy address: ${record.proxyAddress}`);
  console.log(`Implementation address: ${record.implementationAddress}`);
  for (const facet of record.facets) {
    console.log(`${facet.contractName} address: ${facet.address}`);
  }
  console.log(`Deployment record: ${outputPath}`);
}

await main();
