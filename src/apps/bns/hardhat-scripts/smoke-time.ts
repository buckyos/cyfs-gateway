import assert from "node:assert/strict";

import { encodeBytes32String, ZeroHash } from "ethers";

import { Smoke, auth, chain, keyUpdate, named, options, rule } from "./smoke-common.js";

export async function testTime(s: Smoke): Promise<void> {
  await s.scenario("local: exact block count and timestamp control", async () => s.isolated(async () => {
    const before = BigInt(await s.connection.provider.request({ method: "eth_blockNumber", params: [] }) as string);
    await s.connection.provider.request({ method: "hardhat_mine", params: ["0x5", "0x2"] });
    const after = BigInt(await s.connection.provider.request({ method: "eth_blockNumber", params: [] }) as string);
    assert.equal(after - before, 5n);
  }));

  await s.scenario("local: name expiry boundary, write rejection and renewal past grace", async () => s.isolated(async () => {
    const name = s.name("expiry");
    await s.register(name, options(3600, 1000));
    await s.send("publishDocument", await s.publishArgs(name, "owner", 0, "survives-renewal"));
    const state = await s.read("queryNameState", [name]);
    await s.at(state.expireAt - 1n);
    assert.equal((await s.read("queryNameState", [name])).status, 1n);
    await s.at(state.expireAt);
    assert.equal((await s.read("queryNameState", [name])).status, 2n);
    assert.equal((await s.read("resolveDocument", [name, "owner"])).status, 3n);
    await s.reject("publishDocument", await s.publishArgs(name, "owner", 1, "denied"), "NameNotFound");
    await s.reject("registerName", [`child.${name}`, s.account, options(), [], { kind: 0, value: "0x" }, [], ZeroHash, [], s.ownerAuth, { expectedNameSeq: 0, expectedParentNameSeq: state.nameSeq }], "NameNotFound");
    await s.at(state.graceUntil + 1n);
    const receipt = await s.send("renewName", [name, 3600]);
    const block = await s.connection.ethers.provider.getBlock(receipt.blockNumber);
    const renewed = await s.read("queryNameState", [name]);
    assert.equal(renewed.expireAt, BigInt(block!.timestamp) + 3600n);
    assert.equal(renewed.graceUntil - renewed.expireAt, 1000n);
    assert.equal(renewed.status, 1n);
    assert.equal((await s.read("resolveDocument", [name, "owner"])).status, 1n);
  }));

  await s.scenario("local: independent document expiration boundary", async () => s.isolated(async () => {
    const name = s.name("doc-expiry");
    await s.register(name);
    const expiry = await s.timestamp() + 1000n;
    await s.send("publishDocument", await s.publishArgs(name, "owner", 0, "expires", s.ownerAuth, expiry));
    await s.at(expiry - 1n);
    assert.equal((await s.read("resolveDocument", [name, "owner"])).status, 1n);
    await s.at(expiry);
    assert.equal((await s.read("queryNameState", [name])).status, 1n);
    assert.equal((await s.read("resolveDocument", [name, "owner"])).status, 3n);
    assert.equal((await s.read("getPurchaseContext", [name, "owner"])).status, 3n);
    assert.equal((await s.read("getDocumentVersion", [name, "owner", 1])).status, 1n);
    await s.send("publishDocument", await s.publishArgs(name, "owner", 1, "refreshed"));
    assert.equal((await s.read("resolveDocument", [name, "owner"])).status, 1n);
  }));

  await s.scenario("local: controller validFrom inclusive and validUntil exclusive", async () => s.isolated(async () => {
    const name = s.name("controller-time");
    await s.register(name);
    const start = await s.timestamp() + 1000n;
    const end = start + 1000n;
    const controller = auth(chain(s.account), ZeroHash, 2);
    await s.send("setControllerPolicy", [name, [rule(s.account, "timed", 1, start, end)], ZeroHash, s.ownerAuth, await s.guard(name)]);
    await s.at(start - 1n);
    await s.reject("publishDocument", await s.publishArgs(name, "timed", 0, "denied", controller), "ControllerScopeDenied");
    await s.at(start);
    // eth_call exercises the exact boundary; the subsequent transaction proves persistence.
    await s.bns.getFunction("publishDocument").staticCall(...await s.publishArgs(name, "timed", 0, "valid", controller));
    await s.send("publishDocument", await s.publishArgs(name, "timed", 0, "valid", controller));
    await s.at(end - 1n);
    await s.bns.getFunction("publishDocument").staticCall(...await s.publishArgs(name, "timed", 1, "valid", controller));
    await s.at(end);
    await s.reject("publishDocument", await s.publishArgs(name, "timed", 1, "denied", controller), "ControllerScopeDenied");
  }));

  await s.scenario("local: authority key validity and last-signer safety latch", async () => s.isolated(async () => {
    const authority = s.name("timed-authority");
    const name = s.name("key-time");
    await s.register(authority);
    await s.register(name);
    const start = await s.timestamp() + 1000n;
    const end = start + 1000n;
    const backup = keyUpdate("backup", s.account);
    const timed = keyUpdate("timed", s.account, true, start, end);
    await s.send("updateAuthorityKeys", [authority, [backup, timed], s.ownerAuth, await s.guard(authority)]);
    await s.send("setNameOwner", [name, named(authority), s.ownerAuth, await s.guard(name)]);
    const timedAuth = auth(named(authority), encodeBytes32String("timed"));
    await s.at(start - 1n);
    await s.reject("publishDocument", await s.publishArgs(name, "owner", 0, "denied", timedAuth), "NotEffectiveOwner");
    await s.at(start);
    await s.bns.getFunction("publishDocument").staticCall(...await s.publishArgs(name, "owner", 0, "valid", timedAuth));
    await s.send("publishDocument", await s.publishArgs(name, "owner", 0, "valid", timedAuth));
    await s.send("updateAuthorityKeys", [authority, [{ ...backup, active: false }], s.ownerAuth, await s.guard(authority)]);
    assert.equal((await s.read("getAuthoritySet", [authority])).activeKeyCount, 1n);
    await s.at(end - 1n);
    await s.bns.getFunction("publishDocument").staticCall(...await s.publishArgs(name, "owner", 1, "valid", timedAuth));
    await s.at(end);
    await s.reject("publishDocument", await s.publishArgs(name, "owner", 1, "denied", timedAuth), "NotEffectiveOwner");
    await s.reject("updateAuthorityKeys", [authority, [{ ...timed, active: false }], s.ownerAuth, await s.guard(authority)], "NoConcreteSigner");
    await s.send("updateAuthorityKeys", [authority, [keyUpdate("recovered", s.account)], s.ownerAuth, await s.guard(authority)]);
    await s.send("publishDocument", await s.publishArgs(name, "owner", 1, "recovered", auth(named(authority), encodeBytes32String("recovered"))));
  }));
}
