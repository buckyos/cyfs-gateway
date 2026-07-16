import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { upgrades } from "@openzeppelin/hardhat-upgrades";
import {
  encodeBytes32String,
  getAddress,
  getBytes,
  sha256,
  toUtf8Bytes,
  ZeroAddress,
  ZeroHash,
} from "ethers";
import hre from "hardhat";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const contractDirectory = path.resolve(scriptDirectory, "..");
const facetFunctionNames = JSON.parse(
  await readFile(path.join(scriptDirectory, "facet-manifest.json"), "utf8"),
) as Record<string, readonly string[]>;

async function main(): Promise<void> {
  execFileSync(process.execPath, [path.join(scriptDirectory, "check-facets.mjs")], {
    cwd: contractDirectory,
    stdio: "inherit",
  });

  const connection = await hre.network.create();
  if (connection.networkName !== "anvil") {
    throw new Error(
      `BNS smoke must run with --network anvil, received ${connection.networkName}`,
    );
  }

  const { ethers } = connection;
  const upgradesApi = await upgrades(hre, connection);
  const [signer] = await ethers.getSigners();
  if (signer === undefined) {
    throw new Error("No Anvil account is available for the BNS smoke test");
  }
  const deployer = getAddress(await signer.getAddress());

  console.log(`Smoke deployer: ${deployer}`);
  const cuts = [];
  for (const [contractName, functionNames] of Object.entries(
    facetFunctionNames,
  )) {
    const factory = await ethers.getContractFactory(contractName, signer);
    const facet = await factory.deploy();
    await facet.waitForDeployment();
    const facetAddress = getAddress(await facet.getAddress());
    const selectors = functionNames.map((functionName) => {
      const fragment = facet.interface.getFunction(functionName);
      if (fragment === null) {
        throw new Error(`${contractName} has no function named ${functionName}`);
      }
      return fragment.selector;
    });
    cuts.push({ facet: facetAddress, selectors });
    console.log(`${contractName}: ${facetAddress}`);
  }

  const routerFactory = await ethers.getContractFactory("Bns", signer);
  const router = await upgradesApi.deployProxy(routerFactory, [deployer], {
    kind: "uups",
  });
  await router.waitForDeployment();
  const proxyAddress = getAddress(await router.getAddress());

  const configureTransaction = await router.addFacets(cuts);
  const configureReceipt = await configureTransaction.wait();
  if (configureReceipt === null || configureReceipt.status !== 1) {
    throw new Error("BNS facet configuration reverted");
  }
  console.log(`BNS proxy: ${proxyAddress}`);

  const bns = await ethers.getContractAt("IBns", proxyAddress, signer);
  const unsetPrincipal = { kind: 0, value: "0x" };
  const registerTransaction = await bns.registerName(
    "alice",
    deployer,
    {
      duration: 365n * 24n * 60n * 60n,
      gracePeriod: 30n * 24n * 60n * 60n,
      renewable: true,
      transferable: true,
      initialSemanticOwner: unsetPrincipal,
      allowDelegatedSubnames: false,
      initialPaymentTarget: ZeroAddress,
      initialPaymentPolicyHash: ZeroHash,
      initialNamespacePolicyHash: ZeroHash,
    },
    [],
    unsetPrincipal,
    [],
    ZeroHash,
    [],
    { role: 0, actor: unsetPrincipal, kid: ZeroHash },
    { expectedNameSeq: 0, expectedParentNameSeq: 0 },
  );
  const registerReceipt = await registerTransaction.wait();
  if (registerReceipt === null || registerReceipt.status !== 1) {
    throw new Error("registerName reverted");
  }

  const nameState = await bns.queryNameState("alice");
  if (Number(nameState.status) !== 1 || nameState.assetOwner !== deployer) {
    throw new Error("registered name state is invalid");
  }
  console.log(`registerName: active at nameSeq ${nameState.nameSeq}`);

  const documentBody = toUtf8Bytes('{"id":"did:bns:alice"}');
  const publishTransaction = await bns.publishDocument(
    "alice",
    "owner",
    0,
    {
      storageType: encodeBytes32String("inline"),
      uri: "",
      inlineDocument: documentBody,
      contentHash: sha256(documentBody),
      schema: ZeroHash,
      codec: ZeroHash,
      extraHash: ZeroHash,
    },
    unsetPrincipal,
    unsetPrincipal,
    ZeroAddress,
    0,
    ZeroHash,
    ZeroHash,
    ZeroHash,
    ZeroHash,
    ZeroHash,
    {
      role: 1,
      actor: { kind: 1, value: getBytes(deployer) },
      kid: ZeroHash,
    },
    { expectedNameSeq: nameState.nameSeq, expectedParentNameSeq: 0 },
  );
  const publishReceipt = await publishTransaction.wait();
  if (publishReceipt === null || publishReceipt.status !== 1) {
    throw new Error("publishDocument reverted");
  }

  const resolved = await bns.resolveDocument("alice", "owner");
  if (
    Number(resolved.status) !== 1 ||
    Number(resolved.documentState.version) !== 1
  ) {
    throw new Error("published owner document did not resolve as active version 1");
  }

  console.log("publishDocument: owner version 1");
  console.log("resolveDocument: active");
  console.log("BNS Hardhat-on-Anvil smoke passed");
}

await main();
