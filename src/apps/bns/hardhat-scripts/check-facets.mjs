import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { Interface } from "ethers";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const contractDirectory = path.resolve(scriptDirectory, "..");
const artifactDirectory = path.join(contractDirectory, "artifacts");
const maxRuntimeBytecodeSize = 24_576;

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

function artifactPath(contractName) {
  return path.join(
    artifactDirectory,
    "src",
    `${contractName}.sol`,
    `${contractName}.json`,
  );
}

function functionMap(artifact) {
  const contractInterface = new Interface(artifact.abi);
  const functions = new Map();
  for (const entry of artifact.abi) {
    if (entry.type !== "function") {
      continue;
    }
    const fragment = contractInterface.getFunction(entry.name);
    if (fragment === null) {
      throw new Error(`${artifact.contractName} has no ABI function ${entry.name}`);
    }
    functions.set(fragment.selector, fragment.format("sighash"));
  }
  return { contractInterface, functions };
}

async function storageLayout(artifact) {
  const buildInfo = await readJson(
    path.join(artifactDirectory, "build-info", `${artifact.buildInfoId}.output.json`),
  );
  const compiled =
    buildInfo.output?.contracts?.[artifact.inputSourceName]?.[artifact.contractName];
  if (compiled?.storageLayout === undefined) {
    throw new Error(`No storage layout for ${artifact.contractName}`);
  }
  return compiled.storageLayout;
}

function typeShape(types, typeId) {
  const type = types[typeId];
  if (type === undefined) {
    throw new Error(`Unknown storage type ${typeId}`);
  }
  const shape = {
    encoding: type.encoding,
    label: type.label,
    numberOfBytes: type.numberOfBytes,
  };
  for (const key of ["base", "key", "value"]) {
    if (type[key] !== undefined) {
      shape[key] = typeShape(types, type[key]);
    }
  }
  if (type.members !== undefined) {
    shape.members = type.members.map((member) => ({
      label: member.label,
      offset: member.offset,
      slot: member.slot,
      type: typeShape(types, member.type),
    }));
  }
  return shape;
}

function normalizedStorage(layout) {
  return layout.storage.map((entry) => ({
    label: entry.label,
    offset: entry.offset,
    slot: entry.slot,
    type: typeShape(layout.types, entry.type),
  }));
}

const facetManifest = await readJson(
  path.join(scriptDirectory, "facet-manifest.json"),
);
if (
  facetManifest === null ||
  Array.isArray(facetManifest) ||
  typeof facetManifest !== "object"
) {
  throw new Error("Facet manifest must be an object");
}

const routerArtifact = await readJson(artifactPath("Bns"));
const interfaceArtifact = await readJson(artifactPath("IBns"));
const coreArtifact = await readJson(artifactPath("BnsCore"));
const routerFunctions = functionMap(routerArtifact).functions;
const interfaceFunctions = functionMap(interfaceArtifact).functions;
const coreFunctions = functionMap(coreArtifact).functions;
const expectedBusinessFunctions = new Map(
  [...interfaceFunctions].filter(([selector]) => !routerFunctions.has(selector)),
);
const routerStorage = JSON.stringify(
  normalizedStorage(await storageLayout(routerArtifact)),
);

const assignedSelectors = new Map();
const sizes = [["Bns", (routerArtifact.deployedBytecode.length - 2) / 2]];
for (const [contractName, functionNames] of Object.entries(facetManifest)) {
  if (
    !Array.isArray(functionNames) ||
    functionNames.length === 0 ||
    functionNames.some((name) => typeof name !== "string")
  ) {
    throw new Error(`${contractName} must have a non-empty function-name list`);
  }

  const artifact = await readJson(artifactPath(contractName));
  const { contractInterface, functions } = functionMap(artifact);
  const runtimeSize = (artifact.deployedBytecode.length - 2) / 2;
  sizes.push([contractName, runtimeSize]);
  if (runtimeSize > maxRuntimeBytecodeSize) {
    throw new Error(
      `${contractName} runtime is ${runtimeSize} bytes, exceeding ${maxRuntimeBytecodeSize}`,
    );
  }

  const facetBusinessSelectors = new Set(
    [...functions.keys()].filter((selector) => !coreFunctions.has(selector)),
  );
  const manifestSelectors = new Set();
  for (const functionName of functionNames) {
    const fragment = contractInterface.getFunction(functionName);
    if (fragment === null) {
      throw new Error(`${contractName} has no function named ${functionName}`);
    }
    if (manifestSelectors.has(fragment.selector)) {
      throw new Error(`${contractName} repeats selector ${fragment.selector}`);
    }
    if (routerFunctions.has(fragment.selector)) {
      throw new Error(
        `${contractName}.${functionName} collides with Router selector ${fragment.selector}`,
      );
    }
    const previous = assignedSelectors.get(fragment.selector);
    if (previous !== undefined) {
      throw new Error(
        `${contractName}.${functionName} collides with ${previous} at ${fragment.selector}`,
      );
    }
    manifestSelectors.add(fragment.selector);
    assignedSelectors.set(fragment.selector, `${contractName}.${functionName}`);
  }
  if (
    [...facetBusinessSelectors].some((selector) => !manifestSelectors.has(selector)) ||
    [...manifestSelectors].some((selector) => !facetBusinessSelectors.has(selector))
  ) {
    throw new Error(`${contractName} manifest does not match its public business ABI`);
  }

  const facetStorage = JSON.stringify(
    normalizedStorage(await storageLayout(artifact)),
  );
  if (facetStorage !== routerStorage) {
    throw new Error(`${contractName} storage layout differs from the Bns Router`);
  }
}

if (
  [...expectedBusinessFunctions.keys()].some(
    (selector) => !assignedSelectors.has(selector),
  ) ||
  [...assignedSelectors.keys()].some(
    (selector) => !expectedBusinessFunctions.has(selector),
  )
) {
  throw new Error("Facet manifest does not cover the complete IBns business ABI");
}

for (const [contractName, runtimeSize] of sizes) {
  if (runtimeSize > maxRuntimeBytecodeSize) {
    throw new Error(
      `${contractName} runtime is ${runtimeSize} bytes, exceeding ${maxRuntimeBytecodeSize}`,
    );
  }
  console.log(`${contractName}: ${runtimeSize} runtime bytes`);
}
console.log(
  `Facet manifest: ${assignedSelectors.size} selectors; storage layouts match the Router`,
);
