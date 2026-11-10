import assert from "node:assert/strict";

import { Contract, ZeroAddress } from "ethers";

import { Smoke } from "./smoke-common.js";

export async function testAdmin(s: Smoke): Promise<void> {
  await s.scenario("local: facet replacement, removal, restoration and access control", async () => s.isolated(async () => {
    const selector = s.bns.getFunction("queryNameState").fragment.selector;
    const original = await s.read("facetForSelector", [selector]);
    await s.reject("removeFacet", [[selector]], "OwnableUnauthorizedAccount", s.other);
    await s.reject("addFacets", [[{ facet: original, selectors: [selector] }]], "FacetSelectorAlreadyAssigned");
    await s.reject("replaceFacet", [s.other, [selector]], "FacetHasNoCode");
    await s.reject("addFacets", [[{ facet: original, selectors: [s.bns.getFunction("owner").fragment.selector] }]], "ProtectedFacetSelector");
    const replacement = await (await s.connection.ethers.getContractFactory("BnsResolverFacet")).deploy();
    await replacement.waitForDeployment();
    await s.send("replaceFacet", [await replacement.getAddress(), [selector]], "FacetSelectorReplaced");
    assert.equal(await s.read("facetForSelector", [selector]), await replacement.getAddress());
    assert.equal((await s.read("queryNameState", [s.name("main")])).assetOwner, s.account);
    await s.send("removeFacet", [[selector]], "FacetSelectorRemoved");
    assert.equal(await s.read("facetForSelector", [selector]), ZeroAddress);
    await s.reject("queryNameState", [s.name("main")], "FacetSelectorNotAssigned");
    await s.send("addFacets", [[{ facet: original, selectors: [selector] }]], "FacetSelectorAdded");
    assert.equal((await s.read("queryNameState", [s.name("main")])).assetOwner, s.account);
  }));

  await s.scenario("local: UUPS upgrade preserves state; ownership transfer and renunciation", async () => s.isolated(async () => {
    const factory = await s.connection.ethers.getContractFactory("Bns");
    const implementation = await factory.deploy();
    await implementation.waitForDeployment();
    const address = await implementation.getAddress();
    const implementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
    assert.equal(await implementation.proxiableUUID(), implementationSlot);
    s.covered.add("proxiableUUID");
    const direct = new Contract(address, s.bns.interface, s.bns.runner);
    await s.reject("initialize", [s.account], "InvalidInitialization", undefined, direct);
    await s.reject("upgradeToAndCall", [address, "0x"], "OwnableUnauthorizedAccount", s.other);
    const before = await s.read("queryNameState", [s.name("main")]);
    const root = await s.read("currentLogRoot");
    await s.send("upgradeToAndCall", [address, "0x"], "Upgraded");
    const stored = await s.connection.ethers.provider.getStorage(String(s.bns.target), implementationSlot);
    assert.equal(stored.slice(-40).toLowerCase(), address.slice(2).toLowerCase());
    assert.equal((await s.read("queryNameState", [s.name("main")])).nameSeq, before.nameSeq);
    assert.equal(await s.read("currentLogRoot"), root);
    await s.reject("transferOwnership", [ZeroAddress], "OwnableInvalidOwner");
    await s.reject("transferOwnership", [s.other], "OwnableUnauthorizedAccount", s.other);
    await s.send("transferOwnership", [s.other], "OwnershipTransferred");
    assert.equal(await s.read("owner"), s.other);
    await s.reject("renounceOwnership", [], "OwnableUnauthorizedAccount");
  }));

  await s.scenario("local: renounce upgrade ownership on isolated proxy state", async () => s.isolated(async () => {
    await s.send("renounceOwnership", [], "OwnershipTransferred");
    assert.equal(await s.read("owner"), ZeroAddress);
    await s.reject("addFacets", [[]], "OwnableUnauthorizedAccount");
  }));
}
