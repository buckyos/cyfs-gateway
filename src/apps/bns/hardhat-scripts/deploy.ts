import { execFileSync } from "node:child_process";
import { mkdir, rename, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import hre from "hardhat";

import {
  checkFacets,
  contractDirectory,
  deployBns,
  readDeploymentNetwork,
  scriptDirectory,
} from "./deploy-common.js";

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
    path.join(contractDirectory, "src")
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
  checkFacets();

  const connection = await hre.network.create();
  const network = await readDeploymentNetwork(connection);
  const outputPath = path.join(
    contractDirectory,
    "deployments",
    `${deploymentSlug(network.networkName, network.chainId)}.json`,
  );
  await assertOutputDoesNotExist(outputPath);

  console.log(`Source commit: ${commit}`);
  const deployment = await deployBns(connection, network);
  const record = {
    schemaVersion: 2,
    network: deployment.networkName,
    chainId: deployment.chainId,
    deployedAt: new Date().toISOString(),
    deploymentCommitHash: commit,
    proxyType: "uups",
    deployer: deployment.deployer,
    upgradeAdmin: deployment.upgradeAdmin,
    proxyAddress: deployment.proxyAddress,
    implementationAddress: deployment.implementationAddress,
    implementationBytecodeSize: deployment.implementationBytecodeSize,
    facets: deployment.facets,
    facetConfigurationTransaction:
      deployment.facetConfigurationTransaction,
    proxyDeploymentTransaction: deployment.proxyDeploymentTransaction,
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
