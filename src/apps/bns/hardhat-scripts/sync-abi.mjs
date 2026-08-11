import { copyFile, mkdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const contractDirectory = path.resolve(scriptDirectory, "..");
const generatedBindingPath = path.join(
  contractDirectory,
  "bindings",
  "BnsBindings.sol",
);
const destinationBindingPath = path.resolve(
  contractDirectory,
  "..",
  "..",
  "components",
  "bns-evm",
  "abi",
  "BnsBindings.sol",
);

async function readGeneratedBinding() {
  try {
    return await readFile(generatedBindingPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `Generated binding is missing; run \`npm run compile\` first: ${generatedBindingPath}`,
      );
    }
    throw error;
  }
}

const generatedBinding = await readGeneratedBinding();

if (process.argv.includes("--check")) {
  let destinationBinding;
  try {
    destinationBinding = await readFile(destinationBindingPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      console.error(`Synchronized binding is missing: ${destinationBindingPath}`);
      process.exitCode = 1;
    } else {
      throw error;
    }
  }
  if (
    destinationBinding !== undefined &&
    destinationBinding !== generatedBinding
  ) {
    console.error(
      `Synchronized binding is out of date; run \`npm run abi:sync\`: ${destinationBindingPath}`,
    );
    process.exitCode = 1;
  }
} else {
  await mkdir(path.dirname(destinationBindingPath), { recursive: true });
  await copyFile(generatedBindingPath, destinationBindingPath);
}
