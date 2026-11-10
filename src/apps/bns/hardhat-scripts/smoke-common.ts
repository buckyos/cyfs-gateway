import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";

import {
  Contract, Interface, VoidSigner, encodeBytes32String, getAddress, getBytes,
  isError, sha256, toUtf8Bytes, ZeroAddress, ZeroHash,
} from "ethers";
import type { ContractTransactionResponse, TransactionReceipt } from "ethers";
import hre from "hardhat";
import type { NetworkConnection } from "hardhat/types/network";

export const unset = { kind: 0, value: "0x" };
export const chain = (address: string) => ({ kind: 1, value: getBytes(address) });
export const named = (name: string) => ({ kind: 2, value: toUtf8Bytes(name) });
export const auth = (actor: ReturnType<typeof chain>, kid = ZeroHash, role = 1) => ({ role, actor, kid });
export const noAuth = { role: 0, actor: unset, kid: ZeroHash };
export const noPolicy = { updateMinDocumentIat: false, minDocumentIat: 0, reasonHash: ZeroHash };
export const hash = (value: string) => sha256(toUtf8Bytes(value));
export const inline = (value: string) => ({
  storageType: encodeBytes32String("inline"), uri: "", inlineDocument: toUtf8Bytes(value),
  contentHash: hash(value), schema: ZeroHash, codec: ZeroHash, extraHash: ZeroHash,
});
export const documentUpdate = (docType: string, value: string, expectedVersion = 0) => ({
  docType, expectedVersion, document: inline(value), controller: unset, beneficiary: unset,
  paymentTarget: ZeroAddress, expireAt: 0, controllerPolicyHash: ZeroHash,
  paymentPolicyHash: ZeroHash, splitPolicyHash: ZeroHash, pricePolicyHash: ZeroHash, rightsPolicyHash: ZeroHash,
});
export const options = (duration = 365 * 86400, gracePeriod = 30 * 86400) => ({
  duration, gracePeriod, renewable: true, transferable: true, initialSemanticOwner: unset,
  allowDelegatedSubnames: true, initialPaymentTarget: ZeroAddress,
  initialPaymentPolicyHash: ZeroHash, initialNamespacePolicyHash: ZeroHash,
});
export const keyUpdate = (kid: string, account: string, active = true, validFrom = 0n, validUntil = 0n) => ({
  key: {
    kid: encodeBytes32String(kid), verificationMethod: encodeBytes32String("eip155-account"),
    keyData: getBytes(account), purposes: 1, validFrom, validUntil, status: 1, metadataHash: ZeroHash,
  }, active,
});
export const rule = (account: string, docType: string, permissions: number, validFrom = 0n, validUntil = 0n) => ({
  controller: chain(account), docType, permissions, namespaceScopeHash: ZeroHash,
  validFrom, validUntil, constraintHash: ZeroHash,
});

export const facetManifest = JSON.parse(await readFile(
  new URL("./facet-manifest.json", import.meta.url), "utf8",
)) as Record<string, string[]>;

const businessEvents: Record<string, string> = {
  registerName: "NameRegistered", transferName: "NameAssetTransferred", applyMutations: "ProtocolEvent",
  renewName: "NameRenewed", setNameOwner: "NameOwnerUpdated", releaseName: "NameReleased",
  setNamespacePolicy: "NamespacePolicyUpdated", updateAuthorityKeys: "AuthorityKeysUpdated",
  setMinDocumentIat: "OwnerDocumentIatFloorUpdated", publishDocument: "DocumentPublished",
  revokeDocument: "DocumentRevoked", setControllerPolicy: "ControllerPolicyUpdated",
  setDidAlias: "DidAliasSet", setPaymentTarget: "PaymentTargetUpdated", publishLogCheckpoint: "LogCheckpointPublished",
};

export class Smoke {
  readonly covered = new Set<string>();
  readonly prefix = `smoke${randomBytes(8).toString("hex")}`;
  readonly other = getAddress(`0x${randomBytes(20).toString("hex")}`);
  readonly ownerAuth;
  cases = 0;
  transactions = 0;
  rejections = 0;

  constructor(
    readonly connection: NetworkConnection,
    readonly bns: Contract,
    readonly account: string,
  ) {
    this.ownerAuth = auth(chain(account));
  }

  static async create(connection: NetworkConnection, address: string): Promise<Smoke> {
    assert.notEqual(await connection.ethers.provider.getCode(address), "0x", `No BNS contract code at ${address}`);
    const [signer] = await connection.ethers.getSigners();
    assert(signer, `No smoke test account configured for ${connection.networkName}`);
    // IBns alone omits errors inherited by concrete facets. Merge the production
    // ABIs so a negative test must match the precise on-chain custom error.
    const artifacts = await Promise.all(["IBns", "Bns", ...Object.keys(facetManifest)].map(
      (name) => hre.artifacts.readArtifact(name).then((artifact) => new Interface(artifact.abi)),
    ));
    const abi = new Interface([...new Set(artifacts.flatMap((abi) => abi.fragments.map((f) => f.format("full"))))]);
    const smoke = new Smoke(connection, new Contract(address, abi, signer), getAddress(await signer.getAddress()));
    console.log(`Smoke account: ${smoke.account}\nBNS proxy: ${address}\nSmoke prefix: ${smoke.prefix}`);
    return smoke;
  }

  name(suffix: string): string { return `${this.prefix}-${suffix}`; }

  async read(method: string, args: unknown[] = []) {
    const value = await this.bns.getFunction(method).staticCall(...args);
    this.covered.add(method);
    return value;
  }

  async send(method: string, args: unknown[], event = businessEvents[method]): Promise<TransactionReceipt> {
    const tx = await this.bns.getFunction(method)(...args) as ContractTransactionResponse;
    console.log(`  ${method}: ${tx.hash}`);
    const receipt = await tx.wait();
    assert(receipt && receipt.status === 1, `${method} transaction failed: ${tx.hash}`);
    const logs = receipt.logs.filter((log) => getAddress(log.address) === getAddress(String(this.bns.target)))
      .map((log) => this.bns.interface.parseLog(log)).filter((log) => log !== null);
    if (event) assert(logs.some((log) => log.name === event), `${method}: missing ${event}`);
    const protocol = logs.filter((log) => log.name === "ProtocolEvent");
    if (businessEvents[method]) assert(protocol.length > 0, `${method}: missing ProtocolEvent`);
    for (let i = 0; i < protocol.length; i++) {
      assert.equal(getAddress(protocol[i].args.actor), this.account, "ProtocolEvent actor");
      assert.notEqual(protocol[i].args.logRoot, protocol[i].args.previousLogRoot, "log root must change");
      if (i > 0) {
        assert.equal(protocol[i].args.seq, protocol[i - 1].args.seq + 1n, "event sequence in receipt");
        assert.equal(protocol[i].args.previousLogRoot, protocol[i - 1].args.logRoot, "log root chain in receipt");
      }
    }
    this.covered.add(method);
    this.transactions++;
    return receipt;
  }

  async reject(method: string, args: unknown[], expectedError: string, sender?: string, target = this.bns): Promise<void> {
    const contract = sender ? target.connect(new VoidSigner(sender, this.connection.ethers.provider)) : target;
    await assert.rejects(() => contract.getFunction(method).staticCall(...args), (error: unknown) => {
      // Ethers uses error.data; Hardhat may wrap revert bytes in error.data.data.
      let data: unknown = error;
      for (let depth = 0; depth < 4 && typeof data === "object" && data !== null && "data" in data; depth++) data = data.data;
      if (typeof data !== "string" || !/^0x[0-9a-fA-F]+$/.test(data)) return false;
      const decoded = this.bns.interface.parseError(data);
      assert.equal(decoded?.name, expectedError, `${method}: unexpected revert`);
      return true;
    }, `${method} must revert with ${expectedError}`);
    this.rejections++;
  }

  async revertedTransaction(method: string, args: unknown[], expectedError: string): Promise<void> {
    await this.reject(method, args, expectedError);
    // Bypass estimation so the VM must execute and roll back an actual mined
    // transaction, rather than testing only eth_call's simulated state.
    const gasLimit = 3_000_000n;
    const tx = await this.bns.getFunction(method)(...args, { gasLimit }) as ContractTransactionResponse;
    console.log(`  ${method} (expected revert): ${tx.hash}`);
    let receipt: TransactionReceipt | null;
    try { receipt = await tx.wait(); } catch (error) {
      if (!isError(error, "CALL_EXCEPTION") || !error.receipt) throw error;
      receipt = error.receipt;
    }
    assert(receipt && receipt.status === 0, `${method}: expected a mined failed transaction`);
    assert(receipt.gasUsed < gasLimit, `${method}: unexpected out-of-gas failure`);
    assert.equal(receipt.logs.length, 0, "reverted transaction must roll back logs");
    this.transactions++;
  }

  async scenario(label: string, run: () => Promise<void>): Promise<void> {
    console.log(`[RUN] ${label}`);
    try { await run(); } catch (error) { throw new Error(`Smoke scenario failed: ${label}`, { cause: error }); }
    this.cases++;
    console.log(`[PASS] ${label}`);
  }

  async guard(name: string, parent?: string) {
    return {
      expectedNameSeq: (await this.read("queryNameState", [name])).nameSeq,
      expectedParentNameSeq: parent ? (await this.read("queryNameState", [parent])).nameSeq : 0n,
    };
  }

  async register(name: string, opts = options(), parent?: string, docs: ReturnType<typeof documentUpdate>[] = []) {
    return this.send("registerName", [name, this.account, opts, [], unset, [], ZeroHash, docs,
      parent ? this.ownerAuth : noAuth, { expectedNameSeq: 0, expectedParentNameSeq: parent ? (await this.guard(parent)).expectedNameSeq : 0 }]);
  }

  async publishArgs(name: string, docType: string, version: number, value: string, authority = this.ownerAuth, expireAt = 0n, parent?: string) {
    return [name, docType, version, inline(value), unset, unset, ZeroAddress, expireAt,
      ZeroHash, ZeroHash, ZeroHash, ZeroHash, ZeroHash, authority, await this.guard(name, parent)];
  }

  async timestamp(): Promise<bigint> {
    const block = await this.connection.provider.request({ method: "eth_getBlockByNumber", params: ["latest", false] }) as { timestamp: string };
    return BigInt(block.timestamp);
  }

  async at(timestamp: bigint): Promise<void> {
    await this.connection.provider.request({ method: "evm_setNextBlockTimestamp", params: [Number(timestamp)] });
    await this.connection.provider.request({ method: "evm_mine", params: [] });
    assert.equal(await this.timestamp(), timestamp, "mined timestamp");
  }

  async isolated(run: () => Promise<void>): Promise<void> {
    const snapshot = await this.connection.provider.request({ method: "evm_snapshot", params: [] });
    try { await run(); } finally {
      assert.equal(await this.connection.provider.request({ method: "evm_revert", params: [snapshot] }), true, "restore local snapshot");
    }
  }

  report(): void {
    const business = Object.values(facetManifest).flat();
    const missing = business.filter((method) => !this.covered.has(method));
    console.log(`Business interfaces: ${business.length - missing.length}/${business.length} successful calls`);
    assert.deepEqual(missing, [], "business interfaces missing from smoke");
    console.log(`Smoke passed: ${this.cases} scenarios, ${this.transactions} confirmed transactions, ${this.rejections} expected reverts`);
    console.log(`Successful interfaces: ${[...this.covered].sort().join(", ")}`);
  }
}
