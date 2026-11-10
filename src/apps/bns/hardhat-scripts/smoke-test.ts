import assert from "node:assert/strict";

import { encodeBytes32String, hexlify, ZeroAddress, ZeroHash } from "ethers";

import {
  Smoke, auth, chain, documentUpdate, facetManifest, hash, inline, keyUpdate,
  named, noAuth, noPolicy, options, rule, unset,
} from "./smoke-common.js";

export async function testBns(s: Smoke): Promise<void> {
  const main = s.name("main");
  const authority = s.name("authority");
  const controller = auth(chain(s.account), ZeroHash, 2);

  await s.scenario("constants, router selectors and missing-state queries", async () => {
    const constants: Record<string, bigint | string> = {
      MAX_INLINE_DOCUMENT: 4096n, MAX_MUTATION_BATCH_ITEMS: 32n,
      MAX_MUTATION_BATCH_INLINE_DOCUMENTS: 65536n, MAX_OWNER_REF_DEPTH: 8n,
      KEY_PURPOSE_AUTHENTICATION: 1n, KEY_PURPOSE_RECOVERY: 2n, KEY_PURPOSE_SIGN_DOCUMENT: 4n,
      PERMISSION_PUBLISH_DOCUMENT: 1n, PERMISSION_REVOKE_DOCUMENT: 2n,
      PERMISSION_SET_PAYMENT: 4n, PERMISSION_SET_ALIAS: 8n, PERMISSION_SET_NAMESPACE: 16n,
      STORAGE_INLINE: encodeBytes32String("inline"), UPGRADE_INTERFACE_VERSION: "5.0.0",
    };
    for (const [method, expected] of Object.entries(constants)) assert.equal(await s.read(method), expected, method);
    assert.notEqual(await s.read("owner"), ZeroAddress);
    for (const methods of Object.values(facetManifest)) {
      for (const method of methods) {
        const selector = s.bns.getFunction(method).fragment.selector;
        const facet = await s.read("facetForSelector", [selector]);
        assert.notEqual(facet, ZeroAddress, `${method}: missing facet`);
        assert.notEqual(await s.connection.ethers.provider.getCode(facet), "0x", `${method}: facet has no code`);
      }
    }
    assert.equal((await s.read("chainAccountPrincipal", [s.account])).value, s.account.toLowerCase());
    assert.equal((await s.read("bnsNamePrincipal", [main])).value, hexlify(named(main).value));
    assert.equal((await s.read("queryNameState", [main])).status, 0n);
    await s.reject("queryNameState", ["Invalid_Name"], "InvalidName");
    await s.reject("resolveOwner", [main], "NameNotFound");
    await s.reject("initialize", [s.account], "InvalidInitialization");
    await s.reject("proxiableUUID", [], "UUPSUnauthorizedCallContext");
  });

  await s.scenario("registration bootstrap, document versions, hashes and input limits", async () => {
    await s.register(main, options(), undefined, [documentUpdate("owner", "owner-v1")]);
    const state = await s.read("queryNameState", [main]);
    assert.equal(state.status, 1n);
    assert.equal(state.assetOwner, s.account);
    assert.equal(state.nameSeq, 1n);
    assert.equal(state.ownerDocumentVersion, 1n);
    assert.equal((await s.read("resolveOwner", [main])).source, 1n);
    assert.equal(await s.read("isStandardTransferEnabled", [main]), true);
    assert.equal((await s.read("resolveDocument", [main, "missing"])).status, 0n);
    await s.reject("registerName", [main, s.account, options(), [], unset, [], ZeroHash, [], noAuth, { expectedNameSeq: 0, expectedParentNameSeq: 0 }], "NameAlreadyExists");
    const args = await s.publishArgs(main, "owner", 1, "owner-v2");
    await s.reject("publishDocument", [...args.slice(0, -1), { expectedNameSeq: 0, expectedParentNameSeq: 0 }], "StaleNameSeq");
    await s.reject("publishDocument", [main, "owner", 0, ...args.slice(3)], "StaleDocumentVersion");
    await s.reject("publishDocument", [main, "BAD TYPE", 0, ...args.slice(3)], "InvalidDocType");
    await s.reject("publishDocument", [main, "owner", 1, { ...inline("x"), contentHash: ZeroHash }, ...args.slice(4)], "InvalidMutation");
    await s.reject("publishDocument", await s.publishArgs(main, "owner", 1, "x".repeat(4097)), "InlineDocumentTooLarge");
    await s.reject("publishDocument", args, "NotEffectiveOwner", s.other);
    await s.send("publishDocument", args);
    const resolved = await s.read("resolveDocument", [main, "owner"]);
    assert.equal(resolved.status, 1n);
    assert.equal(resolved.documentState.version, 2n);
    assert.equal(resolved.documentState.previousVersion, 1n);
    assert.equal(resolved.documentState.document.contentHash, hash("owner-v2"));
    assert.equal(resolved.documentState.document.inlineDocument, hexlify(inline("owner-v2").inlineDocument));
    assert.equal((await s.read("getDocumentVersion", [main, "owner", 1])).document.contentHash, hash("owner-v1"));
    await s.send("publishDocument", await s.publishArgs(main, "large", 0, "x".repeat(4096)));
    assert.equal((await s.read("resolveDocument", [main, "large"])).documentState.document.inlineDocument.length, 8194);
    const refArgs = await s.publishArgs(main, "reference", 0, "external-body");
    refArgs[3] = { ...inline("external-body"), storageType: encodeBytes32String("ipfs"), uri: "ipfs://bns-smoke", inlineDocument: new Uint8Array() };
    await s.send("publishDocument", refArgs);
    assert.equal((await s.read("resolveDocument", [main, "reference"])).documentState.document.uri, "ipfs://bns-smoke");
    await s.send("revokeDocument", [main, "owner", 2, hash("revoke"), s.ownerAuth, await s.guard(main)]);
    assert.equal((await s.read("resolveDocument", [main, "owner"])).status, 2n);
    assert.equal((await s.read("getDocumentVersion", [main, "owner", 2])).status, 1n);
    await s.send("publishDocument", await s.publishArgs(main, "owner", 3, "owner-v4"));
    assert.equal((await s.read("resolveDocument", [main, "owner"])).documentState.version, 4n);
  });

  await s.scenario("atomic registration bootstraps keys, semantic owner, policy and documents", async () => {
    const name = s.name("bootstrap");
    const key = keyUpdate("bootstrap", s.account);
    await s.send("registerName", [name, s.account, options(), [key], named(name),
      [rule(s.account, "service", 1)], hash("bootstrap-policy"), [documentUpdate("owner", "bootstrap-owner")],
      noAuth, { expectedNameSeq: 0, expectedParentNameSeq: 0 }]);
    const state = await s.read("queryNameState", [name]);
    assert.equal(state.ownerSource, 2n);
    assert.equal(state.ownerDocumentVersion, 1n);
    assert.equal((await s.read("getAuthoritySet", [name])).activeKeyCount, 1n);
    await s.reject("publishDocument", await s.publishArgs(name, "owner", 1, "denied"), "NotEffectiveOwner");
    await s.send("publishDocument", await s.publishArgs(name, "owner", 1, "bootstrap-v2", auth(named(name), key.key.kid)));
    await s.send("publishDocument", await s.publishArgs(name, "service", 0, "bootstrap-service", controller));
    assert.equal((await s.read("resolveDocument", [name, "service"])).documentState.document.contentHash, hash("bootstrap-service"));
  });

  await s.scenario("payment metadata, purchase context and DID alias kinds", async () => {
    const hashes = [hash("payment"), hash("split"), hash("price"), hash("rights")];
    await s.send("setPaymentTarget", [main, "owner", 4, s.other, chain(s.other), ...hashes, s.ownerAuth, await s.guard(main)]);
    const payment = await s.read("resolvePaymentTarget", [main, "owner", 4]);
    assert.equal(payment.paymentTarget, s.other);
    assert.equal(payment.beneficiary.value, s.other.toLowerCase());
    assert.deepEqual([payment.paymentPolicyHash, payment.splitPolicyHash, payment.pricePolicyHash, payment.rightsPolicyHash], hashes);
    const purchase = await s.read("getPurchaseContext", [main, "owner"]);
    assert.equal(purchase.documentVersion, 4n);
    assert.equal(purchase.paymentTarget, s.other);
    assert.equal(purchase.status, 1n);
    assert.equal(purchase.paymentPolicyHash, hashes[0]);
    await s.reject("getPurchaseContext", [main, "missing"], "DocumentNotFound");
    await s.reject("setPaymentTarget", [main, "owner", 3, s.other, unset, ...hashes, s.ownerAuth, await s.guard(main)], "StaleDocumentVersion");
    for (const kind of [1, 2, 3, 0]) {
      const target = kind === 0 ? "" : `did:bns:${main}`;
      await s.send("setDidAlias", [main, target, kind, hash(`alias${kind}`), s.ownerAuth, await s.guard(main)]);
      const alias = await s.read("getAlias", [main]);
      assert.equal(alias.kind, BigInt(kind));
      assert.equal(alias.targetDid, target);
      assert.equal((await s.read("resolveDocument", [main, "owner"])).aliasKind, BigInt(kind));
    }
    await s.reject("setDidAlias", [main, "not-a-did", 1, ZeroHash, s.ownerAuth, await s.guard(main)], "InvalidMutation");
  });

  await s.scenario("namespace policy, subname inheritance and parent sequence guard", async () => {
    await s.send("setNamespacePolicy", [main, true, hash("namespace"), s.ownerAuth, await s.guard(main)]);
    const parent = await s.read("queryNameState", [main]);
    assert.equal(parent.namespacePolicyHash, hash("namespace"));
    assert.equal(parent.allowDelegatedSubnames, true);
    const child = `child.${main}`;
    const args = [child, s.account, options(), [], unset, [], ZeroHash, [], s.ownerAuth, { expectedNameSeq: 0, expectedParentNameSeq: 0 }];
    await s.reject("registerName", args, "StaleParentNameSeq");
    args[args.length - 1] = { expectedNameSeq: 0, expectedParentNameSeq: parent.nameSeq };
    await s.reject("registerName", args, "NotEffectiveOwner", s.other);
    await s.register(child, options(), main);
    assert.equal((await s.read("resolveOwner", [child])).source, 3n);
    assert.equal(await s.read("isStandardTransferEnabled", [child]), false);
    await s.send("publishDocument", await s.publishArgs(child, "owner", 0, "child-owner", s.ownerAuth, 0n, main));
    await s.send("setNamespacePolicy", [main, false, ZeroHash, s.ownerAuth, await s.guard(main)]);
    assert.equal((await s.read("queryNameState", [main])).allowDelegatedSubnames, false);
  });

  await s.scenario("authority keys, semantic ownership, key rotation and atomic transfer", async () => {
    await s.register(authority);
    const oldKey = keyUpdate("old", s.account);
    const newKey = keyUpdate("new", s.account);
    await s.send("updateAuthorityKeys", [authority, [oldKey], s.ownerAuth, await s.guard(authority)]);
    const set = await s.read("getAuthoritySet", [authority]);
    assert.equal(set.activeKeyCount, 1n);
    assert.equal(set.authoritySeq, 1n);
    assert.notEqual(set.authorityRoot, ZeroHash);
    assert.equal((await s.read("getAuthorityKey", [authority, oldKey.key.kid])).keyData, s.account.toLowerCase());
    await s.send("setNameOwner", [main, named(authority), s.ownerAuth, await s.guard(main)]);
    assert.equal((await s.read("resolveOwner", [main])).effectiveOwner.value, hexlify(named(authority).value));
    assert.equal((await s.read("resolveOwner", [main])).authorityRoot, set.authorityRoot);
    assert.equal(await s.read("isStandardTransferEnabled", [main]), false);
    await s.reject("publishDocument", await s.publishArgs(main, "authority", 0, "denied"), "NotEffectiveOwner");
    await s.send("publishDocument", await s.publishArgs(main, "authority", 0, "old-key", auth(named(authority), oldKey.key.kid)));
    await s.send("updateAuthorityKeys", [authority, [{ ...oldKey, active: false }, newKey], s.ownerAuth, await s.guard(authority)]);
    assert.equal((await s.read("getAuthorityKey", [authority, oldKey.key.kid])).status, 2n);
    assert.equal((await s.read("getAuthoritySet", [authority])).authoritySeq, 2n);
    await s.reject("publishDocument", await s.publishArgs(main, "authority", 1, "denied", auth(named(authority), oldKey.key.kid)), "NotEffectiveOwner");
    await s.reject("updateAuthorityKeys", [authority, [{ ...newKey, active: false }], s.ownerAuth, await s.guard(authority)], "NoConcreteSigner");
    const keyAuth = auth(named(authority), newKey.key.kid);
    await s.send("transferName", [main, s.other, named(authority), [documentUpdate("transfer", "atomic-transfer")], keyAuth, await s.guard(main)]);
    assert.equal((await s.read("queryNameState", [main])).assetOwner, s.other);
    assert.equal((await s.read("resolveDocument", [main, "transfer"])).documentState.document.contentHash, hash("atomic-transfer"));
    await s.send("transferName", [main, s.account, unset, [], keyAuth, await s.guard(main)]);
    assert.equal(await s.read("isStandardTransferEnabled", [main]), true);
    assert.equal((await s.read("queryNameState", [main])).assetOwner, s.account);
  });

  await s.scenario("controller scopes, permission bits, policy replacement and revocation", async () => {
    await s.send("setControllerPolicy", [main, [rule(s.account, "controlled", 1)], hash("scoped"), s.ownerAuth, await s.guard(main)]);
    await s.reject("publishDocument", await s.publishArgs(main, "owner", 4, "denied", controller), "ControllerScopeDenied");
    await s.reject("publishDocument", await s.publishArgs(main, "controlled", 0, "denied", auth(chain(s.other), ZeroHash, 2)), "ControllerScopeDenied", s.other);
    await s.send("publishDocument", await s.publishArgs(main, "controlled", 0, "controller-v1", controller));
    await s.reject("revokeDocument", [main, "controlled", 1, ZeroHash, controller, await s.guard(main)], "ControllerScopeDenied");
    await s.send("setControllerPolicy", [main, [rule(s.account, "", 31)], hash("all-permissions"), s.ownerAuth, await s.guard(main)]);
    await s.send("setPaymentTarget", [main, "controlled", 1, s.other, unset, ZeroHash, ZeroHash, ZeroHash, ZeroHash, controller, await s.guard(main)]);
    await s.send("setDidAlias", [main, `did:bns:${authority}`, 1, ZeroHash, controller, await s.guard(main)]);
    await s.send("setNamespacePolicy", [main, true, ZeroHash, controller, await s.guard(main)]);
    await s.send("revokeDocument", [main, "controlled", 1, ZeroHash, controller, await s.guard(main)]);
    assert.equal((await s.read("resolveDocument", [main, "controlled"])).status, 2n);
    await s.send("setControllerPolicy", [main, [], ZeroHash, s.ownerAuth, await s.guard(main)]);
    await s.reject("publishDocument", await s.publishArgs(main, "controlled", 2, "denied", controller), "ControllerScopeDenied");
  });

  await s.scenario("atomic batches, sequence increments and IAT floor monotonicity", async () => {
    const before = await s.read("queryNameState", [main]);
    const docs = [documentUpdate("batch-a", "A"), documentUpdate("batch-b", "B")];
    const policy = { updateMinDocumentIat: true, minDocumentIat: 10, reasonHash: hash("batch-floor") };
    await s.send("applyMutations", [main, [keyUpdate("batch", s.account)], docs, policy, s.ownerAuth, await s.guard(main)]);
    const after = await s.read("queryNameState", [main]);
    assert.equal(after.nameSeq, before.nameSeq + 1n);
    assert.equal(after.ownerPolicySeq, before.ownerPolicySeq + 1n);
    assert.equal(after.minDocumentIat, 10n);
    for (const doc of docs) assert.equal((await s.read("resolveDocument", [main, doc.docType])).documentState.document.contentHash, doc.document.contentHash);
    assert.equal((await s.read("getAuthoritySet", [main])).activeKeyCount, 1n);
    await s.reject("applyMutations", [main, [], [], noPolicy, s.ownerAuth, await s.guard(main)], "InvalidMutation");
    await s.reject("applyMutations", [main, [], [documentUpdate("duplicate", "1"), documentUpdate("duplicate", "2")], noPolicy, s.ownerAuth, await s.guard(main)], "InvalidMutation");
    const rollback = [documentUpdate("rollback", "must-not-persist"), documentUpdate("batch-a", "stale", 0)];
    const rootBefore = await s.read("currentLogRoot");
    const eventsBefore = await s.read("globalEventSeq");
    await s.revertedTransaction("applyMutations", [main, [], rollback, noPolicy, s.ownerAuth, await s.guard(main)], "StaleDocumentVersion");
    assert.equal((await s.read("resolveDocument", [main, "rollback"])).status, 0n);
    assert.equal((await s.read("queryNameState", [main])).nameSeq, after.nameSeq);
    // Only local runs own the entire chain. On a shared external chain other
    // clients may advance the global log while our failed transaction is mined.
    if (s.connection.networkConfig.type === "edr-simulated" || s.connection.networkName === "localhost") {
      assert.equal(await s.read("currentLogRoot"), rootBefore);
      assert.equal(await s.read("globalEventSeq"), eventsBefore);
    }
    const keysOnlySeq = (await s.read("queryNameState", [main])).nameSeq;
    await s.send("applyMutations", [main, [keyUpdate("batch-extra", s.account)], [], noPolicy, s.ownerAuth, await s.guard(main)]);
    assert.equal((await s.read("queryNameState", [main])).nameSeq, keysOnlySeq);
    await s.reject("applyMutations", [main, [], Array.from({ length: 33 }, (_, i) => documentUpdate(`limit-${i}`, "x")), noPolicy, s.ownerAuth, await s.guard(main)], "InvalidMutation");
    await s.send("setMinDocumentIat", [main, 20, hash("new-floor"), s.ownerAuth, await s.guard(main)]);
    await s.reject("setMinDocumentIat", [main, 19, ZeroHash, s.ownerAuth, await s.guard(main)], "InvalidMutation");
    assert.equal((await s.read("queryNameState", [main])).minDocumentIat, 20n);
  });

  await s.scenario("renewal, release, lineage reset and permanent tombstone", async () => {
    const life = s.name("life");
    await s.register(life, options(), undefined, [documentUpdate("owner", "old-lineage")]);
    await s.send("setDidAlias", [life, `did:bns:${main}`, 1, ZeroHash, s.ownerAuth, await s.guard(life)]);
    await s.send("updateAuthorityKeys", [life, [keyUpdate("lineage", s.account)], s.ownerAuth, await s.guard(life)]);
    await s.send("setControllerPolicy", [life, [rule(s.account, "controlled", 1)], ZeroHash, s.ownerAuth, await s.guard(life)]);
    const before = await s.read("queryNameState", [life]);
    await s.send("renewName", [life, 86400]);
    assert.equal((await s.read("queryNameState", [life])).expireAt, before.expireAt + 86400n);
    await s.reject("renewName", [life, 0], "InvalidMutation");
    const fixed = s.name("nonrenewable");
    await s.register(fixed, { ...options(), renewable: false });
    await s.reject("renewName", [fixed, 86400], "InvalidMutation");
    await s.send("releaseName", [life, 0, hash("release"), s.ownerAuth, await s.guard(life)]);
    assert.equal((await s.read("queryNameState", [life])).status, 3n);
    assert.equal((await s.read("resolveDocument", [life, "owner"])).status, 3n);
    await s.reject("publishDocument", await s.publishArgs(life, "owner", 1, "denied"), "NameNotFound");
    await s.register(life);
    assert.equal((await s.read("queryNameState", [life])).lineageEpoch, 1n);
    assert.equal((await s.read("resolveDocument", [life, "owner"])).status, 0n);
    assert.equal((await s.read("getDocumentVersion", [life, "owner", 1])).document.contentHash, hash("old-lineage"));
    assert.equal((await s.read("getAlias", [life])).kind, 0n);
    assert.equal((await s.read("getAuthoritySet", [life])).activeKeyCount, 0n);
    await s.reject("publishDocument", await s.publishArgs(life, "controlled", 0, "denied", controller), "ControllerScopeDenied");
    await s.send("publishDocument", await s.publishArgs(life, "owner", 0, "new-lineage"));
    assert.equal((await s.read("resolveDocument", [life, "owner"])).documentState.version, 2n);
    await s.send("releaseName", [life, 1, hash("tombstone"), s.ownerAuth, await s.guard(life)]);
    assert.equal((await s.read("queryNameState", [life])).status, 4n);
    assert.equal((await s.read("resolveDocument", [life, "owner"])).status, 5n);
    await s.reject("registerName", [life, s.account, options(), [], unset, [], ZeroHash, [], noAuth, { expectedNameSeq: 0, expectedParentNameSeq: 0 }], "NameAlreadyExists");
    await s.reject("renewName", [life, 86400], "InvalidMutation");
  });

  await s.scenario("protocol log chain and checkpoint snapshot", async () => {
    const anchor = hash(s.prefix);
    const receipt = await s.send("publishLogCheckpoint", [chain(s.account), anchor]);
    const checkpointEvent = receipt.logs.map((log) => {
      try { return s.bns.interface.parseLog(log); } catch { return null; }
    }).find((log) => log?.name === "LogCheckpointPublished");
    assert(checkpointEvent);
    const checkpoint = await s.read("latestCheckpoint");
    assert.equal(checkpoint.externalAnchor, anchor);
    assert.equal(checkpoint.logRoot, checkpointEvent.args.logRoot);
    assert.equal(checkpoint.lastSeq, checkpointEvent.args.lastSeq);
    assert.equal(checkpoint.issuer.value, s.account.toLowerCase());
    const block = await s.connection.ethers.provider.getBlock(receipt.blockNumber);
    assert.equal(checkpoint.issuedAt, BigInt(block!.timestamp));
    assert((await s.read("globalEventSeq")) > checkpoint.lastSeq);
    assert.notEqual(await s.read("currentLogRoot"), checkpoint.logRoot);
  });
}
