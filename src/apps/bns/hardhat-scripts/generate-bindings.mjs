import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const contractDirectory = path.resolve(scriptDirectory, "..");
const buildInfoDirectory = path.join(contractDirectory, "artifacts", "build-info");

function artifactPath(contractName) {
  return path.join(
    contractDirectory,
    "artifacts",
    "src",
    `${contractName}.sol`,
    `${contractName}.json`,
  );
}

const interfaceArtifactPath = artifactPath("IBns");
const supplementalArtifactPaths = [
  "Bns",
  "BnsResolverFacet",
  "BnsRegistrationFacet",
  "BnsAtomicMutationFacet",
  "BnsNameFacet",
  "BnsAuthorityFacet",
  "BnsDocumentFacet",
  "BnsAliasPaymentFacet",
].map(artifactPath);
const solidityBindingPath = path.join(
  contractDirectory,
  "bindings",
  "BnsBindings.sol",
);

function canonicalType(input) {
  if (!input.type.startsWith("tuple")) {
    return input.type;
  }
  const suffix = input.type.slice("tuple".length);
  return `(${(input.components ?? []).map(canonicalType).join(",")})${suffix}`;
}

function abiKey(entry) {
  const inputs = (entry.inputs ?? []).map(canonicalType).join(",");
  return `${entry.type}:${entry.name ?? ""}(${inputs})`;
}

async function readArtifactAbi(artifactPathValue) {
  const artifact = JSON.parse(await readFile(artifactPathValue, "utf8"));
  if (!Array.isArray(artifact.abi)) {
    throw new Error(`Hardhat artifact has no ABI array: ${artifactPathValue}`);
  }
  return artifact.abi;
}

async function aggregateAbi() {
  const abi = [...(await readArtifactAbi(interfaceArtifactPath))];
  const knownEntries = new Set(abi.map(abiKey));

  for (const artifactPathValue of supplementalArtifactPaths) {
    for (const entry of await readArtifactAbi(artifactPathValue)) {
      const key = abiKey(entry);
      if (!knownEntries.has(key)) {
        knownEntries.add(key);
        abi.push(entry);
      }
    }
  }

  return abi;
}

function enumDefinitionsFromAst(ast) {
  return (ast?.nodes ?? [])
    .filter((node) => node.nodeType === "EnumDefinition")
    .map((node) => ({
      name: node.name,
      members: (node.members ?? []).map((member) => member.name),
    }));
}

async function loadEnumDefinitions() {
  let entries;
  try {
    entries = await readdir(buildInfoDirectory);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `Hardhat build info is missing; run \`hardhat build\` first: ${buildInfoDirectory}`,
      );
    }
    throw error;
  }

  let canonicalDefinitions;
  let canonicalSource;
  for (const entry of entries.filter((name) => name.endsWith(".output.json")).sort()) {
    const buildInfoPath = path.join(buildInfoDirectory, entry);
    const buildInfo = JSON.parse(await readFile(buildInfoPath, "utf8"));
    for (const [sourceName, sourceOutput] of Object.entries(
      buildInfo.output?.sources ?? {},
    )) {
      if (!sourceName.endsWith("/src/BnsTypes.sol")) {
        continue;
      }
      const definitions = enumDefinitionsFromAst(sourceOutput.ast);
      if (definitions.length === 0) {
        throw new Error(`No enum definitions found in ${buildInfoPath}:${sourceName}`);
      }
      if (canonicalDefinitions === undefined) {
        canonicalDefinitions = definitions;
        canonicalSource = `${buildInfoPath}:${sourceName}`;
      } else if (
        JSON.stringify(definitions) !== JSON.stringify(canonicalDefinitions)
      ) {
        throw new Error(
          `BnsTypes enum definitions disagree between ${canonicalSource} and ${buildInfoPath}:${sourceName}`,
        );
      }
    }
  }

  if (canonicalDefinitions === undefined) {
    throw new Error(
      `No BnsTypes.sol AST found under Hardhat build info: ${buildInfoDirectory}`,
    );
  }
  return canonicalDefinitions;
}

function namedInternalType(internalType, keyword) {
  const value = internalType.slice(`${keyword} `.length);
  const match = /^([A-Za-z_$][A-Za-z0-9_$.]*)((?:\[[0-9]*\])*)$/.exec(value);
  if (match === null) {
    throw new Error(`Unsupported ${keyword} internalType: ${internalType}`);
  }
  const name = match[1].split(".").at(-1);
  return `${name}${match[2]}`;
}

function solidityType(parameter) {
  const internalType = parameter.internalType;
  if (internalType?.startsWith("struct ")) {
    return namedInternalType(internalType, "struct");
  }
  if (internalType?.startsWith("enum ")) {
    return namedInternalType(internalType, "enum");
  }
  if (internalType?.startsWith("contract ")) {
    const contractType = namedInternalType(internalType, "contract");
    const arrayOffset = contractType.indexOf("[");
    return `address${arrayOffset < 0 ? "" : contractType.slice(arrayOffset)}`;
  }
  if (internalType?.startsWith("interface ")) {
    const interfaceType = namedInternalType(internalType, "interface");
    const arrayOffset = interfaceType.indexOf("[");
    return `address${arrayOffset < 0 ? "" : interfaceType.slice(arrayOffset)}`;
  }
  if (parameter.type.startsWith("tuple")) {
    throw new Error(
      `Tuple parameter ${parameter.name || "<unnamed>"} has no named struct internalType`,
    );
  }
  return parameter.type;
}

function structName(parameter) {
  if (!parameter.internalType?.startsWith("struct ")) {
    return undefined;
  }
  return namedInternalType(parameter.internalType, "struct").split("[")[0];
}

function collectStructDefinitions(abi) {
  const definitions = new Map();
  const visiting = new Set();

  function visit(parameter) {
    for (const component of parameter.components ?? []) {
      visit(component);
    }

    const name = structName(parameter);
    if (name === undefined || (parameter.components ?? []).length === 0) {
      return;
    }
    if (visiting.has(name)) {
      throw new Error(`Recursive ABI struct is unsupported: ${name}`);
    }
    const fields = parameter.components.map((component) => ({
      name: component.name,
      type: solidityType(component),
    }));
    if (fields.some((field) => field.name === "")) {
      throw new Error(`Struct ${name} contains an unnamed field`);
    }

    const existing = definitions.get(name);
    if (existing !== undefined && JSON.stringify(existing) !== JSON.stringify(fields)) {
      throw new Error(`Conflicting ABI definitions for struct ${name}`);
    }
    if (existing === undefined) {
      visiting.add(name);
      definitions.set(name, fields);
      visiting.delete(name);
    }
  }

  for (const entry of abi) {
    for (const parameter of [...(entry.inputs ?? []), ...(entry.outputs ?? [])]) {
      visit(parameter);
    }
  }
  return definitions;
}

function referencedEnumNames(abi) {
  const names = new Set();

  function visit(parameter) {
    if (parameter.internalType?.startsWith("enum ")) {
      names.add(namedInternalType(parameter.internalType, "enum").split("[")[0]);
    }
    for (const component of parameter.components ?? []) {
      visit(component);
    }
  }

  for (const entry of abi) {
    for (const parameter of [...(entry.inputs ?? []), ...(entry.outputs ?? [])]) {
      visit(parameter);
    }
  }
  return names;
}

function isReferenceType(parameter) {
  const type = solidityType(parameter);
  return (
    type === "string" ||
    type === "bytes" ||
    type.includes("[") ||
    parameter.internalType?.startsWith("struct ") === true
  );
}

function formatParameter(parameter, { indexed = false, location } = {}) {
  const parts = [solidityType(parameter)];
  if (location !== undefined && isReferenceType(parameter)) {
    parts.push(location);
  }
  if (indexed && parameter.indexed) {
    parts.push("indexed");
  }
  if (parameter.name) {
    parts.push(parameter.name);
  }
  return parts.join(" ");
}

function formatInterfaceEntry(entry) {
  if (entry.type === "error") {
    return `    error ${entry.name}(${(entry.inputs ?? [])
      .map((parameter) => formatParameter(parameter))
      .join(", ")});`;
  }
  if (entry.type === "event") {
    return `    event ${entry.name}(${(entry.inputs ?? [])
      .map((parameter) => formatParameter(parameter, { indexed: true }))
      .join(", ")});`;
  }
  if (entry.type === "function") {
    const inputs = (entry.inputs ?? [])
      .map((parameter) => formatParameter(parameter, { location: "calldata" }))
      .join(", ");
    const stateMutability =
      entry.stateMutability === "view" || entry.stateMutability === "pure"
        ? ` ${entry.stateMutability}`
        : entry.stateMutability === "payable"
          ? " payable"
          : "";
    const outputs = entry.outputs ?? [];
    const returns =
      outputs.length === 0
        ? ""
        : ` returns (${outputs
            .map((parameter) => formatParameter(parameter, { location: "memory" }))
            .join(", ")})`;
    return `    function ${entry.name}(${inputs}) external${stateMutability}${returns};`;
  }
  return undefined;
}

function generateSolidityBinding(abi, enumDefinitions) {
  const referencedEnums = referencedEnumNames(abi);
  const availableEnums = new Map(
    enumDefinitions.map((definition) => [definition.name, definition]),
  );
  for (const name of referencedEnums) {
    if (!availableEnums.has(name)) {
      throw new Error(`ABI enum ${name} is missing from the BnsTypes AST`);
    }
  }

  const enumSource = enumDefinitions
    .filter((definition) => referencedEnums.has(definition.name))
    .map(
      (definition) =>
        `enum ${definition.name} {\n${definition.members
          .map((member) => `    ${member}`)
          .join(",\n")}\n}`,
    )
    .join("\n\n");
  const structSource = [...collectStructDefinitions(abi)]
    .map(
      ([name, fields]) =>
        `struct ${name} {\n${fields
          .map((field) => `    ${field.type} ${field.name};`)
          .join("\n")}\n}`,
    )
    .join("\n\n");
  const interfaceEntries = abi
    .map(formatInterfaceEntry)
    .filter((entry) => entry !== undefined)
    .join("\n");

  return `// SPDX-License-Identifier: MIT
// Generated from the aggregate BNS JSON ABI and Hardhat enum AST by
// hardhat-scripts/generate-bindings.mjs. Do not edit.
pragma solidity ^0.8.24;

${enumSource}

${structSource}

interface Bns {
${interfaceEntries}
}
`;
}

const abi = await aggregateAbi();
const enumDefinitions = await loadEnumDefinitions();
const expectedSolidityBinding = generateSolidityBinding(abi, enumDefinitions);

await mkdir(path.dirname(solidityBindingPath), { recursive: true });
await writeFile(solidityBindingPath, expectedSolidityBinding, "utf8");
