// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// #185: owner writes are local; authority rotations preserve a signer without
/// scanning other names. Historical KIDs remain unbounded within a lineage.
contract BnsOwnerLocalValidationTest is BnsTestBase {
    event GasComparison(uint256 operation, uint256 beforeGrowth, uint256 afterGrowth);

    function _key(bytes32 kid, bool active) internal pure returns (AuthorityKeyUpdate memory) {
        return AuthorityKeyUpdate({
            key: AuthorityKey({
                kid: kid,
                verificationMethod: METHOD_EIP155_ACCOUNT,
                keyData: abi.encodePacked(CAROL),
                purposes: 1,
                validFrom: 0,
                validUntil: 0,
                status: AuthorityKeyStatus.Active,
                metadataHash: ZERO
            }),
            active: active
        });
    }

    function _keys(uint256 count, uint256 offset) internal pure returns (AuthorityKeyUpdate[] memory keys) {
        keys = new AuthorityKeyUpdate[](count);
        for (uint256 i = 0; i < count; i++) {
            keys[i] = _key(bytes32(offset + i + 1), true);
        }
    }

    function _update(string memory name, AuthorityKeyUpdate[] memory keys) internal {
        uint64 seq = bns.queryNameState(name).nameSeq;
        vm.prank(ALICE);
        bns.updateAuthorityKeys(name, keys, _ownerAuth(ALICE), _guard(seq));
    }

    function _bootstrap(string memory name) internal {
        bns.registerName(
            name, ALICE, _defaultOptions(_unset()), _keys(1, 0), _bnsName(name),
            new ControllerRule[](0), ZERO, new DocumentUpdate[](0), _noneAuth(), _guard(0)
        );
    }

    function _child(string memory name, string memory parent) internal {
        uint64 seq = bns.queryNameState(parent).nameSeq;
        vm.prank(ALICE);
        _registerName(
            name, BOB, _defaultOptions(_unset()), new DocumentUpdate[](0),
            _ownerAuth(ALICE), _guard(0, seq)
        );
    }

    function _breakUnrelatedOwner(bool release) internal {
        vm.warp(1000);
        _registerName(
            "authority", ALICE, _options(100, 30, true, true),
            new DocumentUpdate[](0), _noneAuth(), _guard(0)
        );
        _update("authority", _keys(1, 0));
        _registerName(
            "dependent", BOB, _defaultOptions(_bnsName("authority")),
            new DocumentUpdate[](0), _noneAuth(), _guard(0)
        );
        if (release) {
            vm.prank(ALICE);
            bns.releaseName("authority", ReleaseMode.ReleaseAfterGrace, ZERO, _ownerAuth(ALICE), _guard(1));
        } else {
            vm.warp(1100);
        }
        vm.expectRevert(NoConcreteSigner.selector);
        bns.resolveOwner("dependent");
    }

    function _assertUnrelatedWritesWork() internal {
        _registerRoot("healthy", ALICE);
        _bootstrap("bootstrapped");
        vm.prank(ALICE);
        bns.setNameOwner("healthy", _unset(), _ownerAuth(ALICE), _guard(1));
        vm.prank(ALICE);
        bns.transferName("healthy", BOB, _unset(), new DocumentUpdate[](0), _ownerAuth(ALICE), _guard(2));
        assertTrue(bns.queryNameState("healthy").assetOwner == BOB, "unrelated transfer succeeds");
        assertEqUint(bns.getAuthoritySet("bootstrapped").activeKeyCount, 1, "bootstrap succeeds");
    }

    function testExpiredAuthorityDoesNotBlockUnrelatedWrites() public {
        _breakUnrelatedOwner(false);
        _assertUnrelatedWritesWork();
    }

    function testReleasedAuthorityDoesNotBlockUnrelatedWrites() public {
        _breakUnrelatedOwner(true);
        _assertUnrelatedWritesWork();
    }

    function testExpiredParentDoesNotBlockUnrelatedWrites() public {
        vm.warp(1000);
        _registerName(
            "parent", ALICE, _options(100, 30, true, true),
            new DocumentUpdate[](0), _noneAuth(), _guard(0)
        );
        _child("child.parent", "parent");
        vm.warp(1100);
        vm.expectRevert(NoConcreteSigner.selector);
        bns.resolveOwner("child.parent");
        _assertUnrelatedWritesWork();
    }

    function testParentOwnerChangeStillControlsInheritedChild() public {
        _registerRoot("parent", ALICE);
        _child("child.parent", "parent");
        _registerRoot("authority", ALICE);
        _update("authority", _keys(1, 0));
        vm.prank(ALICE);
        bns.setNameOwner("parent", _bnsName("authority"), _ownerAuth(ALICE), _guard(1));

        vm.prank(ALICE);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("child.parent", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(1));
        vm.prank(CAROL);
        _publishDoc("child.parent", "owner", 0, ownerRef, _ownerAuthName("authority", bytes32(uint256(1))), _guard(1));

        vm.prank(CAROL);
        bns.transferName(
            "parent", BOB, _unset(), new DocumentUpdate[](0),
            _ownerAuthName("authority", bytes32(uint256(1))), _guard(2)
        );
        vm.prank(BOB);
        _publishDoc("child.parent", "owner", 1, ownerRef, _ownerAuth(BOB), _guard(2));
    }

    function testMutualAuthorityReferencesAreTerminalsNotRecursiveOwners() public {
        _registerRoot("first", ALICE);
        _registerRoot("second", ALICE);
        _update("first", _keys(1, 0));
        _update("second", _keys(1, 0));
        vm.prank(ALICE);
        bns.setNameOwner("first", _bnsName("second"), _ownerAuth(ALICE), _guard(1));
        vm.prank(ALICE);
        bns.setNameOwner("second", _bnsName("first"), _ownerAuth(ALICE), _guard(1));
        vm.prank(CAROL);
        _publishDoc("first", "owner", 0, ownerRef, _ownerAuthName("second", bytes32(uint256(1))), _guard(2));
        vm.prank(CAROL);
        _publishDoc("second", "owner", 0, ownerRef, _ownerAuthName("first", bytes32(uint256(1))), _guard(2));
    }

    function testInheritedOwnerCannotFallBackThroughAnEmptyAuthority() public {
        _registerRoot("authority", ALICE);
        _update("authority", _keys(1, 0));
        _registerName(
            "parent", ALICE, _defaultOptions(_bnsName("authority")),
            new DocumentUpdate[](0), _noneAuth(), _guard(0)
        );
        vm.prank(ALICE);
        bns.releaseName("authority", ReleaseMode.ReleaseAfterGrace, ZERO, _ownerAuth(ALICE), _guard(1));
        _registerRoot("authority", ALICE); // fresh lineage, no authority keys
        vm.prank(CAROL);
        vm.expectRevert(NoConcreteSigner.selector);
        _registerName(
            "child.parent", BOB, _defaultOptions(_unset()), new DocumentUpdate[](0),
            _ownerAuthName("authority", bytes32(uint256(1))), _guard(0, 1)
        );
    }

    function testCannotRevokeLastKeyEvenWithoutReferences() public {
        _registerRoot("authority", ALICE);
        _update("authority", _keys(1, 0));
        AuthorityKeyUpdate[] memory keys = _keys(1, 0);
        keys[0].active = false;
        vm.prank(ALICE);
        vm.expectRevert(NoConcreteSigner.selector);
        bns.updateAuthorityKeys("authority", keys, _ownerAuth(ALICE), _guard(1));
        assertEqUint(bns.getAuthoritySet("authority").authoritySeq, 1, "failed update rolled back");
        assertTrue(bns.getAuthorityKey("authority", bytes32(uint256(1))).status == AuthorityKeyStatus.Active, "key retained");
    }

    function testCannotRemoveLastAuthenticationPurpose() public {
        _registerRoot("authority", ALICE);
        _update("authority", _keys(1, 0));
        AuthorityKeyUpdate[] memory keys = _keys(1, 0);
        keys[0].key.purposes = 2; // recovery only
        vm.prank(ALICE);
        vm.expectRevert(NoConcreteSigner.selector);
        bns.updateAuthorityKeys("authority", keys, _ownerAuth(ALICE), _guard(1));
    }

    function testRotationRequiresCurrentlyValidReplacementAndIsAtomic() public {
        vm.warp(1000);
        _bootstrap("authority");
        AuthorityKeyUpdate[] memory keys = _keys(2, 0);
        keys[0].active = false;
        keys[1].key.validFrom = 1100;
        vm.prank(CAROL);
        vm.expectRevert(NoConcreteSigner.selector);
        bns.applyMutations(
            "authority", keys, new DocumentUpdate[](0), _noOwnerPolicyUpdate(),
            _ownerAuthName("authority", bytes32(uint256(1))), _guard(1)
        );
        assertTrue(bns.getAuthorityKey("authority", bytes32(uint256(2))).status == AuthorityKeyStatus.Missing, "new key rolled back");
        keys[1].key.validFrom = 1000;
        vm.prank(CAROL);
        bns.applyMutations(
            "authority", keys, new DocumentUpdate[](0), _noOwnerPolicyUpdate(),
            _ownerAuthName("authority", bytes32(uint256(1))), _guard(1)
        );
        assertEqUint(bns.getAuthoritySet("authority").activeKeyCount, 1, "replacement active");
        vm.prank(CAROL);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("authority", "owner", 0, ownerRef, _ownerAuthName("authority", bytes32(uint256(1))), _guard(1));
        vm.prank(CAROL);
        _publishDoc("authority", "owner", 0, ownerRef, _ownerAuthName("authority", bytes32(uint256(2))), _guard(1));
    }

    function testNaturalExpiryDoesNotResetSignerLatch() public {
        vm.warp(1000);
        _registerRoot("authority", ALICE);
        AuthorityKeyUpdate[] memory keys = _keys(1, 0);
        keys[0].key.validUntil = 1100;
        _update("authority", keys);
        vm.warp(1100);
        vm.prank(ALICE);
        vm.expectRevert(NoConcreteSigner.selector);
        bns.updateAuthorityKeys("authority", new AuthorityKeyUpdate[](0), _ownerAuth(ALICE), _guard(1));
        assertEqUint(bns.getAuthoritySet("authority").activeKeyCount, 1, "persisted count remains a snapshot");
        keys[0] = _key(bytes32(uint256(2)), true);
        _update("authority", keys); // asset-owner fallback can restore a current key
        assertEqUint(bns.getAuthoritySet("authority").activeKeyCount, 1, "expired key excluded from new count");
    }

    function testRecoveryOnlySetCanRemainEmptyAndNewLineageResetsLatch() public {
        _registerRoot("authority", ALICE);
        AuthorityKeyUpdate[] memory keys = _keys(1, 0);
        keys[0].key.purposes = 2;
        _update("authority", keys);
        keys[0].active = false;
        _update("authority", keys);
        assertEqUint(bns.getAuthoritySet("authority").activeKeyCount, 0, "recovery-only updates allowed");
        _update("authority", _keys(1, 0));
        vm.prank(ALICE);
        bns.releaseName("authority", ReleaseMode.ReleaseAfterGrace, ZERO, _ownerAuth(ALICE), _guard(1));
        _registerRoot("authority", ALICE);
        _update("authority", keys);
        assertEqUint(bns.getAuthoritySet("authority").activeKeyCount, 0, "new lineage has independent latch");
    }

    function testStandaloneAuthorityBatchLimitAndUnboundedHistory() public {
        _registerRoot("authority", ALICE);
        AuthorityKeyUpdate[] memory oversized = _keys(33, 0);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(InvalidMutation.selector, keccak256("MUTATION_BATCH_TOO_LARGE")));
        bns.updateAuthorityKeys("authority", oversized, _ownerAuth(ALICE), _guard(1));
        _update("authority", _keys(32, 0));
        _update("authority", _keys(32, 32));
        assertEqUint(bns.getAuthoritySet("authority").activeKeyCount, 64, "32 is batch limit, not history limit");
    }

    function _measureWrites() internal returns (uint256[5] memory gasUsed) {
        uint256 start = gasleft();
        _registerRoot("measured", ALICE);
        gasUsed[0] = start - gasleft();
        start = gasleft();
        _bootstrap("measuredboot");
        gasUsed[1] = start - gasleft();
        vm.prank(ALICE);
        start = gasleft();
        bns.setNameOwner("measured", _unset(), _ownerAuth(ALICE), _guard(1));
        gasUsed[2] = start - gasleft();
        vm.prank(ALICE);
        start = gasleft();
        bns.transferName("measured", BOB, _unset(), new DocumentUpdate[](0), _ownerAuth(ALICE), _guard(2));
        gasUsed[3] = start - gasleft();
        AuthorityKeyUpdate[] memory keys = _keys(1, 0);
        keys[0].key.purposes = 2;
        start = gasleft();
        _update("recovery", keys); // zero authentication keys used to scan all names
        gasUsed[4] = start - gasleft();
    }

    function testWriteGasDoesNotGrowWithGlobalNameCount() public {
        _registerRoot("recovery", ALICE);
        uint256 snapshot = vm.snapshotState();
        uint256[5] memory beforeGrowth = _measureWrites();
        assertTrue(vm.revertToState(snapshot), "restore identical measured names");
        for (uint256 i = 0; i < 100; i++) {
            bytes memory label = new bytes(3);
            label[0] = "n";
            label[1] = bytes1(uint8(97 + i / 26));
            label[2] = bytes1(uint8(97 + i % 26));
            _registerRoot(string(label), ALICE);
        }
        uint256[5] memory afterGrowth = _measureWrites();
        for (uint256 i = 0; i < beforeGrowth.length; i++) {
            emit GasComparison(i, beforeGrowth[i], afterGrowth[i]);
            // Allow incidental warm/cold slot and memory differences, but not
            // the hundreds of thousands of gas from a 100-name registry scan.
            assertTrue(afterGrowth[i] <= beforeGrowth[i] + 30_000, "gas grew with unrelated names");
        }
    }
}
