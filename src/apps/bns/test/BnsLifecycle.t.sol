// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/BnsTypes.sol";

import "./BnsTestBase.sol";

/// §1.6 — Name lifecycle & namespace: register / bootstrap / renew / release,
/// namespace policy, DID alias & payment target read-write, log checkpoint.
contract BnsLifecycleTest is BnsTestBase {
    function _seq(string memory name) internal view returns (uint64) {
        return bns.queryNameState(name).nameSeq;
    }

    function _registerWith(string memory name, address owner, RegisterOptions memory opts) internal returns (uint64) {
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        return _registerName(name, owner, opts, noDocs, _noneAuth(), _guard(0));
    }

    // --- renew -------------------------------------------------------------

    function testRenewBeforeExpiryExtendsFromExpireAt() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));
        uint64 expireAt = bns.queryNameState("alice").expireAt;
        assertEqUint(expireAt, 1000 + 100 days, "initial expireAt");

        vm.warp(1000 + 50 days); // before expiry
        uint64 newExpire = bns.renewName("alice", 100 days);
        assertEqUint(newExpire, expireAt + 100 days, "renew stacks on existing expireAt");
    }

    function testRenewAfterExpiryExtendsFromNow() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));

        vm.warp(1000 + 200 days); // past expiry
        uint64 newExpire = bns.renewName("alice", 100 days);
        assertEqUint(newExpire, uint64(1000 + 200 days) + 100 days, "renew rebases on now after expiry");
        assertTrue(bns.queryNameState("alice").status == NameStatus.Active, "renew restores active");
    }

    function testRenewNonRenewableRejected() public {
        _registerWith("alice", ALICE, _options(100 days, 30 days, false, true));
        vm.expectPartialRevert(InvalidMutation.selector);
        bns.renewName("alice", 10 days);
    }

    function testExpiryIsDerivedAndRejectsActiveWrites() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));
        NameState memory active = bns.queryNameState("alice");
        assertTrue(active.status == NameStatus.Active, "initially active");
        assertTrue(active.standardTransferEnabled, "initially transferable");

        vm.warp(active.expireAt);
        NameState memory expired = bns.queryNameState("alice");
        assertTrue(expired.status == NameStatus.Expired, "expiry derived at boundary");
        assertTrue(!expired.standardTransferEnabled, "expired transfer disabled");

        vm.expectPartialRevert(NameNotFound.selector);
        bns.resolveOwner("alice");

        vm.prank(ALICE);
        vm.expectPartialRevert(NameNotFound.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(expired.nameSeq));
    }

    function testNameExpiryExpiresResolutionAndRenewRestoresIt() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));
        uint64 seq = bns.queryNameState("alice").nameSeq;
        vm.prank(ALICE);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(seq));
        assertTrue(bns.resolveDocument("alice", "owner").status == DocumentStatus.Active, "document initially active");

        uint64 expireAt = bns.queryNameState("alice").expireAt;
        vm.warp(expireAt);
        ResolveResult memory expired = bns.resolveDocument("alice", "owner");
        assertTrue(expired.status == DocumentStatus.Expired, "name expiry expires resolution");
        assertTrue(
            bns.getPurchaseContext("alice", "owner").status == DocumentStatus.Expired,
            "name expiry expires purchase context"
        );
        assertTrue(expired.documentState.status == DocumentStatus.Active, "stored document status remains active");

        bns.renewName("alice", 100 days);
        assertTrue(bns.queryNameState("alice").status == NameStatus.Active, "renewed name active");
        assertTrue(bns.resolveDocument("alice", "owner").status == DocumentStatus.Active, "renew restores resolution");
        assertTrue(
            bns.getPurchaseContext("alice", "owner").status == DocumentStatus.Active, "renew restores purchase context"
        );
    }

    function testExpiredParentCannotRegisterSubname() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));
        NameState memory parent = bns.queryNameState("alice");
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        vm.warp(parent.expireAt);
        vm.prank(ALICE);
        vm.expectPartialRevert(NameNotFound.selector);
        _registerName(
            "laptop.alice", ALICE, _defaultOptions(_unset()), noDocs, _ownerAuth(ALICE), _guard(0, parent.nameSeq)
        );
    }

    // --- release / tombstone ----------------------------------------------

    function testReleasedNameRejectsWritesAndCanBeReRegistered() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.releaseName("alice", ReleaseMode.ReleaseAfterGrace, keccak256("done"), _ownerAuth(ALICE), _guard(s));
        assertTrue(bns.queryNameState("alice").status == NameStatus.Released, "released");

        // State writes are rejected on a released name.
        s = _seq("alice");
        vm.prank(ALICE);
        vm.expectPartialRevert(NameNotFound.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));

        // A released name can be claimed again.
        _registerRoot("alice", BOB);
        assertTrue(bns.queryNameState("alice").status == NameStatus.Active, "re-registered active");
        assertTrue(bns.queryNameState("alice").assetOwner == BOB, "new owner after re-register");
    }

    function testReRegistrationIsolatesLineageStateAndPreservesDocumentHistory() public {
        _registerRoot("alice", ALICE);

        DocumentRef memory oldRef = _inlineDoc(bytes("old-lineage"));
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        uint64 oldVersion = _publishDoc(
            "alice", "dns_txt", 0, oldRef, _ownerAuth(ALICE), _guard(s)
        );
        assertEqUint(oldVersion, 1, "first lineage starts at version one");

        s = _seq("alice");
        _installAuthorityKey("alice", KID, ALICE, ALICE, 0, 0, s);

        ControllerRule[] memory rules = _singleRule(
            _chain(CTRL), "dns_txt", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0
        );
        s = _seq("alice");
        vm.prank(ALICE);
        bns.setControllerPolicy(
            "alice", rules, keccak256("old-controller"), _ownerAuth(ALICE), _guard(s)
        );

        s = _seq("alice");
        vm.prank(ALICE);
        bns.setDidAlias(
            "alice",
            "did:web:old.example",
            AliasKind.MigratedTo,
            keccak256("old-alias"),
            _ownerAuth(ALICE),
            _guard(s)
        );

        s = _seq("alice");
        vm.prank(ALICE);
        bns.setPaymentTarget(
            "alice",
            "dns_txt",
            oldVersion,
            ALICE,
            _chain(ALICE),
            keccak256("old-payment"),
            ZERO,
            ZERO,
            ZERO,
            _ownerAuth(ALICE),
            _guard(s)
        );

        s = _seq("alice");
        vm.prank(ALICE);
        bns.releaseName(
            "alice", ReleaseMode.ReleaseAfterGrace, keccak256("done"), _ownerAuth(ALICE), _guard(s)
        );
        uint64 releasedSeq = _seq("alice");

        _registerRoot("alice", BOB);
        NameState memory currentName = bns.queryNameState("alice");
        assertEqUint(currentName.nameSeq, releasedSeq + 1, "name seq remains globally monotonic");
        assertEqUint(currentName.lineageEpoch, 1, "new registration advances lineage");

        ResolveResult memory missing = bns.resolveDocument("alice", "dns_txt");
        assertTrue(missing.status == DocumentStatus.Missing, "old document is not current");
        vm.expectPartialRevert(DocumentNotFound.selector);
        bns.getPurchaseContext("alice", "dns_txt");

        AliasState memory aliasState = bns.getAlias("alice");
        assertTrue(aliasState.kind == AliasKind.None, "old alias is isolated");
        assertTrue(bytes(aliasState.targetDid).length == 0, "old alias target is isolated");
        assertEqUint(bns.getAuthoritySet("alice").activeKeyCount, 0, "old authority set is isolated");
        assertTrue(
            bns.getAuthorityKey("alice", KID).status == AuthorityKeyStatus.Missing,
            "old authority key is isolated"
        );

        DocumentRef memory deniedRef = _inlineDoc(bytes("denied"));
        s = _seq("alice");
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "dns_txt", 0, deniedRef, _controllerAuth(CTRL), _guard(s));

        DocumentRef memory newRef = _inlineDoc(bytes("new-lineage"));
        vm.prank(BOB);
        uint64 newVersion = _publishDoc(
            "alice", "dns_txt", 0, newRef, _ownerAuth(BOB), _guard(s)
        );
        assertEqUint(newVersion, 2, "document history remains globally monotonic");
        assertEqUint(
            bns.getDocumentVersion("alice", "dns_txt", newVersion).previousVersion,
            0,
            "new lineage does not link trust to old lineage"
        );
        assertEqBytes32(
            bns.getDocumentVersion("alice", "dns_txt", oldVersion).document.contentHash,
            oldRef.contentHash,
            "old document remains available by explicit historical version"
        );

        (, address historicalPaymentTarget,,,,,) =
            bns.resolvePaymentTarget("alice", "dns_txt", oldVersion);
        assertTrue(historicalPaymentTarget == ALICE, "explicit historical payment lookup is preserved");
    }

    function testTombstonedNameRejectsWritesAndReRegistration() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.releaseName("alice", ReleaseMode.TombstoneForever, keccak256("evil"), _ownerAuth(ALICE), _guard(s));
        assertTrue(bns.queryNameState("alice").status == NameStatus.Tombstoned, "tombstoned");

        // Writes rejected.
        s = _seq("alice");
        vm.prank(ALICE);
        vm.expectPartialRevert(NameNotFound.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));

        // Re-registration is permanently blocked.
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        vm.expectPartialRevert(NameAlreadyExists.selector);
        _registerName("alice", BOB, _defaultOptions(_unset()), noDocs, _noneAuth(), _guard(0));
    }

    // --- bootstrap (atomic install) ---------------------------------------

    function testBootstrapInstallsAuthorityOwnerAndControllerPolicy() public {
        AuthorityKeyUpdate[] memory keys = new AuthorityKeyUpdate[](1);
        keys[0] = AuthorityKeyUpdate({
            key: AuthorityKey({
                kid: KID,
                verificationMethod: METHOD_EIP155_ACCOUNT,
                keyData: abi.encodePacked(CAROL),
                purposes: bns.KEY_PURPOSE_AUTHENTICATION(),
                validFrom: 0,
                validUntil: 0,
                status: AuthorityKeyStatus.Active,
                metadataHash: ZERO
            }),
            active: true
        });
        ControllerRule[] memory rules = _singleRule(_chain(CTRL), "dns_txt", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0);
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        (uint64 nameSeq, uint64 authoritySeq,) = bns.registerName(
            "zone",
            ALICE,
            _defaultOptions(_unset()),
            keys,
            _bnsName("zone"), // self-owned after authority install
            rules,
            keccak256("ctrl-policy"),
            noDocs,
            _noneAuth(),
            _guard(0)
        );
        assertEqUint(nameSeq, 1, "bootstrap register keeps create nameSeq");
        assertEqUint(authoritySeq, 1, "authority installed");

        NameState memory st = bns.queryNameState("zone");
        assertTrue(st.ownerSource == OwnerSource.ExplicitSemanticOwner, "self semantic owner");
        assertTrue(bns.getAuthoritySet("zone").activeKeyCount >= 1, "authority key installed");

        // The bootstrapped controller policy is effective: CTRL can publish dns_txt.
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        uint64 s = _seq("zone");
        vm.prank(CTRL);
        uint64 v = _publishDoc("zone", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
        assertEqUint(v, 1, "bootstrapped controller can publish");
    }

    // --- namespace policy --------------------------------------------------

    function testSetNamespacePolicyReadWrite() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.setNamespacePolicy("alice", false, keccak256("ns-policy"), _ownerAuth(ALICE), _guard(s));

        NameState memory st = bns.queryNameState("alice");
        assertTrue(!st.allowDelegatedSubnames, "allowDelegatedSubnames updated");
        assertEqBytes32(st.namespacePolicyHash, keccak256("ns-policy"), "namespace policy hash stored");
    }

    // --- DID alias / payment target ---------------------------------------

    function testSetDidAliasReadWrite() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.setDidAlias(
            "alice",
            "did:web:alice.example",
            AliasKind.MigratedTo,
            keccak256("alias-proof"),
            _ownerAuth(ALICE),
            _guard(s)
        );

        AliasState memory a = bns.getAlias("alice");
        assertTrue(a.kind == AliasKind.MigratedTo, "alias kind");
        assertTrue(keccak256(bytes(a.targetDid)) == keccak256(bytes("did:web:alice.example")), "alias target");
        assertEqBytes32(a.proofHash, keccak256("alias-proof"), "alias proof");
    }

    function testSetPaymentTargetReadWrite() public {
        _registerRoot("alice", ALICE);
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        _publishDoc("alice", "dns_txt", 0, r, _ownerAuth(ALICE), _guard(s)); // v1

        s = _seq("alice");
        vm.prank(ALICE);
        bns.setPaymentTarget(
            "alice",
            "dns_txt",
            1,
            BOB,
            _chain(CAROL),
            keccak256("pp"),
            keccak256("sp"),
            keccak256("pr"),
            keccak256("ri"),
            _ownerAuth(ALICE),
            _guard(s)
        );

        (Principal memory beneficiary, address paymentTarget, bytes32 paymentPolicyHash, bytes32 splitPolicyHash,,,) =
            bns.resolvePaymentTarget("alice", "dns_txt", 1);
        assertTrue(paymentTarget == BOB, "payment target");
        assertTrue(beneficiary.kind == PrincipalKind.ChainAccount, "beneficiary kind");
        assertEqBytes32(paymentPolicyHash, keccak256("pp"), "payment policy hash");
        assertEqBytes32(splitPolicyHash, keccak256("sp"), "split policy hash");
    }

    // --- log checkpoint ----------------------------------------------------

    function testPublishLogCheckpointOverwrites() public {
        _registerRoot("alice", ALICE); // advances globalEventSeq

        // The checkpoint snapshots the log as-of just before its own commit event.
        bytes32 rootBefore = bns.currentLogRoot();
        uint64 seqBefore = bns.globalEventSeq();
        bns.publishLogCheckpoint(_chain(ALICE), keccak256("anchor-1"));
        LogCheckpoint memory cp1 = bns.latestCheckpoint();
        assertEqBytes32(cp1.logRoot, rootBefore, "checkpoint logRoot == pre-commit root");
        assertEqUint(cp1.lastSeq, seqBefore, "checkpoint lastSeq == pre-commit seq");
        assertEqBytes32(cp1.externalAnchor, keccak256("anchor-1"), "anchor 1");

        // More activity, then a second checkpoint overwrites the first.
        _registerRoot("bob", BOB);
        bytes32 rootBefore2 = bns.currentLogRoot();
        bns.publishLogCheckpoint(_chain(BOB), keccak256("anchor-2"));
        LogCheckpoint memory cp2 = bns.latestCheckpoint();
        assertEqBytes32(cp2.logRoot, rootBefore2, "checkpoint2 logRoot == pre-commit root");
        assertTrue(cp2.lastSeq > cp1.lastSeq, "lastSeq advanced");
        assertEqBytes32(cp2.externalAnchor, keccak256("anchor-2"), "anchor 2 overwrote anchor 1");
    }
}
