import { upgrades } from "@openzeppelin/hardhat-upgrades";
import hre from "hardhat";

const connection = await hre.network.create();
const Bns = await connection.ethers.getContractFactory("Bns");
const upgradesApi = await upgrades(hre, connection);

await upgradesApi.validateImplementation(Bns, { kind: "uups" });
console.log("BNS implementation passed OpenZeppelin UUPS upgrade-safety validation");
