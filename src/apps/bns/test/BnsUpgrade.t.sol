// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { OwnableUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import "./BnsTestBase.sol";

contract BnsV2ForTest is Bns {
    function implementationVersion() external pure returns (uint256) {
        return 2;
    }
}

contract BnsUpgradeTest is BnsTestBase {
    function testProxyIsInitializedExactlyOnce() public {
        assertTrue(bns.owner() == address(this), "unexpected upgrade admin");
        vm.expectPartialRevert(Initializable.InvalidInitialization.selector);
        bns.initialize(address(this));
    }

    function testImplementationInitializersAreDisabled() public {
        Bns implementation = new Bns();
        vm.expectPartialRevert(Initializable.InvalidInitialization.selector);
        implementation.initialize(address(this));
    }

    function testZeroUpgradeAdminIsRejected() public {
        Bns implementation = new Bns();
        vm.expectPartialRevert(OwnableUpgradeable.OwnableInvalidOwner.selector);
        new BnsProxy(
            address(implementation), abi.encodeCall(Bns.initialize, (address(0)))
        );
    }

    function testUpgradeAdminCanUpgradeAndStateSurvives() public {
        _registerRoot("alice", ALICE);
        NameState memory beforeUpgrade = bns.queryNameState("alice");
        bytes32 logRootBefore = bns.currentLogRoot();

        BnsV2ForTest nextImplementation = new BnsV2ForTest();
        bns.upgradeToAndCall(address(nextImplementation), "");

        BnsV2ForTest upgraded = BnsV2ForTest(address(bns));
        assertEqUint(upgraded.implementationVersion(), 2, "implementation not upgraded");
        NameState memory afterUpgrade = upgraded.queryNameState("alice");
        assertEqUint(afterUpgrade.nameSeq, beforeUpgrade.nameSeq, "name seq changed");
        assertTrue(afterUpgrade.assetOwner == beforeUpgrade.assetOwner, "asset owner changed");
        assertEqBytes32(upgraded.currentLogRoot(), logRootBefore, "log root changed");
        assertTrue(upgraded.owner() == address(this), "upgrade admin changed");
    }

    function testNonAdminCannotUpgrade() public {
        BnsV2ForTest nextImplementation = new BnsV2ForTest();

        vm.prank(ALICE);
        vm.expectPartialRevert(OwnableUpgradeable.OwnableUnauthorizedAccount.selector);
        bns.upgradeToAndCall(address(nextImplementation), "");
    }
}
