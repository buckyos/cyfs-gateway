import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const contractDirectory = path.resolve(scriptDirectory, "..");
const artifactPath = path.join(
  contractDirectory,
  "artifacts",
  "src",
  "Bns.sol",
  "Bns.json",
);
const abiPath = path.resolve(
  contractDirectory,
  "..",
  "..",
  "components",
  "bns-evm",
  "abi",
  "Bns.json",
);

const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
if (!Array.isArray(artifact.abi)) {
  throw new Error(`Hardhat artifact has no ABI array: ${artifactPath}`);
}

const expected = `${JSON.stringify(artifact.abi, null, 2)}\n`;
if (process.argv.includes("--check")) {
  let actual;
  try {
    actual = await readFile(abiPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      console.error(`Committed ABI is missing: ${abiPath}`);
      process.exitCode = 1;
    } else {
      throw error;
    }
  }
  if (actual !== undefined && actual !== expected) {
    console.error("Committed BNS ABI is out of date; run `npm run compile`.");
    process.exitCode = 1;
  }
} else {
  await mkdir(path.dirname(abiPath), { recursive: true });
  await writeFile(abiPath, expected, "utf8");
}
