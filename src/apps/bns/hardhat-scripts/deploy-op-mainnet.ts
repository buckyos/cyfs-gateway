import { execFileSync } from "node:child_process";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { network } from "hardhat";
import { encodeFunctionData, getAddress, type Address, type Hex } from "viem";

const OP_MAINNET_CHAIN_ID = 10;
const EIP170_CODE_SIZE_LIMIT = 24_576;
const IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as Hex;
const DEPLOY_CONFIRMATION = "OP_MAINNET";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const contractDirectory = path.resolve(scriptDirectory, "..");
const artifactPath = path.join(
  contractDirectory,
  "artifacts",
  "src",
  "Bns.sol",
  "Bns.json",
);
const outputPath = path.join(contractDirectory, "deployments", "op-mainnet.json");

const initializeAbi = [
  {
    type: "function",
    name: "initialize",
    stateMutability: "nonpayable",
    inputs: [{ name: "upgradeAdmin", type: "address" }],
    outputs: [],
  },
] as const;

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

async function assertOutputDoesNotExist(): Promise<void> {
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

async function implementationCodeSize(): Promise<number> {
  const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as {
    deployedBytecode?: string;
  };
  const deployedBytecode = artifact.deployedBytecode;
  if (deployedBytecode === undefined || !deployedBytecode.startsWith("0x")) {
    throw new Error(`Invalid BNS artifact deployedBytecode: ${artifactPath}`);
  }
  return (deployedBytecode.length - 2) / 2;
}

function parseConfirmations(): number {
  const confirmations = Number(process.env.BNS_DEPLOY_CONFIRMATIONS ?? "2");
  if (!Number.isSafeInteger(confirmations) || confirmations < 1 || confirmations > 64) {
    throw new Error("BNS_DEPLOY_CONFIRMATIONS must be an integer between 1 and 64");
  }
  return confirmations;
}

function addressFromSlot(value: Hex | undefined, label: string): Address {
  if (value === undefined) {
    throw new Error(`${label} slot is empty`);
  }
  return getAddress(`0x${value.slice(-40)}`);
}

async function main(): Promise<void> {
  const repoRoot = git(contractDirectory, ["rev-parse", "--show-toplevel"]);
  const commit = assertDeploymentInputsCommitted(repoRoot);
  await assertOutputDoesNotExist();

  const codeSize = await implementationCodeSize();
  console.log(`BNS implementation bytecode: ${codeSize} bytes`);
  if (codeSize > EIP170_CODE_SIZE_LIMIT) {
    throw new Error(
      `BNS implementation exceeds the EIP-170 limit by ${codeSize - EIP170_CODE_SIZE_LIMIT} bytes ` +
        `(${codeSize} > ${EIP170_CODE_SIZE_LIMIT}). Resolve contract sizing before OP Mainnet deployment.`,
    );
  }

  if (process.env.BNS_DEPLOY_CONFIRMATION !== DEPLOY_CONFIRMATION) {
    throw new Error(
      `Set BNS_DEPLOY_CONFIRMATION=${DEPLOY_CONFIRMATION} to confirm an OP Mainnet deployment.`,
    );
  }

  const upgradeAdminValue = process.env.BNS_UPGRADE_ADMIN;
  if (upgradeAdminValue === undefined) {
    throw new Error("BNS_UPGRADE_ADMIN is required");
  }
  const upgradeAdmin = getAddress(upgradeAdminValue);
  const confirmations = parseConfirmations();

  const connection = await network.create();
  if (connection.networkName !== "opMainnet") {
    throw new Error(`Expected Hardhat network opMainnet, got ${connection.networkName}`);
  }

  const { viem } = connection;
  const publicClient = await viem.getPublicClient();
  const [walletClient] = await viem.getWalletClients();
  if (walletClient?.account === undefined) {
    throw new Error("No deployment account configured for opMainnet");
  }

  const chainId = await publicClient.getChainId();
  if (chainId !== OP_MAINNET_CHAIN_ID) {
    throw new Error(`Expected OP Mainnet chain ID 10, got ${chainId}`);
  }

  const deployer = getAddress(walletClient.account.address);
  console.log(`Deploying from: ${deployer}`);
  console.log(`Upgrade admin: ${upgradeAdmin}`);
  console.log(`Source commit: ${commit}`);

  const {
    contract: implementation,
    deploymentTransaction: implementationTransaction,
  } = await viem.sendDeploymentTransaction("Bns");
  const implementationReceipt = await publicClient.waitForTransactionReceipt({
    hash: implementationTransaction.hash,
    confirmations,
  });
  if (implementationReceipt.status !== "success") {
    throw new Error(`BNS implementation deployment reverted: ${implementationTransaction.hash}`);
  }

  const initializationData = encodeFunctionData({
    abi: initializeAbi,
    functionName: "initialize",
    args: [upgradeAdmin],
  });
  const { contract: proxy, deploymentTransaction: proxyTransaction } =
    await viem.sendDeploymentTransaction("BnsProxy", [
      implementation.address,
      initializationData,
    ]);
  const proxyReceipt = await publicClient.waitForTransactionReceipt({
    hash: proxyTransaction.hash,
    confirmations,
  });
  if (proxyReceipt.status !== "success") {
    throw new Error(`BNS proxy deployment reverted: ${proxyTransaction.hash}`);
  }

  const implementationInProxy = addressFromSlot(
    await publicClient.getStorageAt({
      address: proxy.address,
      slot: IMPLEMENTATION_SLOT,
    }),
    "ERC-1967 implementation",
  );
  if (implementationInProxy !== getAddress(implementation.address)) {
    throw new Error(
      `Proxy implementation mismatch: ${implementationInProxy} != ${implementation.address}`,
    );
  }

  const deployedBns = await viem.getContractAt("Bns", proxy.address);
  const configuredUpgradeAdmin = getAddress(
    (await deployedBns.read.owner()) as Address,
  );
  if (configuredUpgradeAdmin !== upgradeAdmin) {
    throw new Error(
      `Proxy upgrade admin mismatch: ${configuredUpgradeAdmin} != ${upgradeAdmin}`,
    );
  }

  const record = {
    schemaVersion: 1,
    network: "op-mainnet",
    chainId,
    deployedAt: new Date().toISOString(),
    deploymentCommitHash: commit,
    proxyType: "uups",
    deployer,
    upgradeAdmin,
    proxyAddress: getAddress(proxy.address),
    implementationAddress: getAddress(implementation.address),
    implementationBytecodeSize: codeSize,
    transactions: {
      implementation: {
        hash: implementationTransaction.hash,
        blockNumber: implementationReceipt.blockNumber.toString(),
      },
      proxy: {
        hash: proxyTransaction.hash,
        blockNumber: proxyReceipt.blockNumber.toString(),
      },
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
  console.log(`Deployment record: ${outputPath}`);
}

await main();
