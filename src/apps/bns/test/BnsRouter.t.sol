// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { OwnableUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {
    FacetSelectorAlreadyAssigned,
    FacetSelectorNotAssigned,
    ProtectedFacetSelector
} from "../src/Bns.sol";
import { BnsRegistrationFacet } from "../src/BnsRegistrationFacet.sol";
import { BnsResolverFacet } from "../src/BnsResolverFacet.sol";
import { IBns } from "../src/IBns.sol";
import "../src/BnsTypes.sol";
import "./BnsTestBase.sol";

contract BnsRouterTest is BnsTestBase {
    function testBusinessSelectorsAreInstalled() public view {
        assertTrue(
            bns.facetForSelector(IBns.registerName.selector) != address(0),
            "registration selector missing"
        );
        assertTrue(
            bns.facetForSelector(IBns.resolveDocument.selector) != address(0),
            "resolver selector missing"
        );
    }

    function testDuplicateSelectorIsRejected() public {
        FacetCut[] memory cuts = new FacetCut[](1);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IBns.registerName.selector;
        cuts[0] = FacetCut({ facet: address(new BnsRegistrationFacet()), selectors: selectors });

        vm.expectPartialRevert(FacetSelectorAlreadyAssigned.selector);
        bns.addFacets(cuts);
    }

    function testNonOwnerCannotManageSelectors() public {
        FacetCut[] memory cuts = new FacetCut[](1);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("newFunction()"));
        cuts[0] = FacetCut({ facet: address(new BnsResolverFacet()), selectors: selectors });

        vm.prank(ALICE);
        vm.expectPartialRevert(OwnableUpgradeable.OwnableUnauthorizedAccount.selector);
        bns.addFacets(cuts);
    }

    function testProtectedRouterSelectorIsRejected() public {
        FacetCut[] memory cuts = new FacetCut[](1);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IBns.owner.selector;
        cuts[0] = FacetCut({ facet: address(new BnsResolverFacet()), selectors: selectors });

        vm.expectPartialRevert(ProtectedFacetSelector.selector);
        bns.addFacets(cuts);
    }

    function testUupsVersionSelectorIsProtected() public {
        FacetCut[] memory cuts = new FacetCut[](1);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IBns.UPGRADE_INTERFACE_VERSION.selector;
        cuts[0] = FacetCut({ facet: address(new BnsResolverFacet()), selectors: selectors });

        vm.expectPartialRevert(ProtectedFacetSelector.selector);
        bns.addFacets(cuts);
    }

    function testReplacingFacetPreservesSharedState() public {
        _registerRoot("alice", ALICE);
        NameState memory beforeReplace = bns.queryNameState("alice");
        BnsResolverFacet replacement = new BnsResolverFacet();
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IBns.queryNameState.selector;

        bns.replaceFacet(address(replacement), selectors);

        assertTrue(
            bns.facetForSelector(IBns.queryNameState.selector) == address(replacement),
            "replacement not installed"
        );
        NameState memory afterReplace = bns.queryNameState("alice");
        assertEqUint(afterReplace.nameSeq, beforeReplace.nameSeq, "name seq changed");
        assertTrue(afterReplace.assetOwner == beforeReplace.assetOwner, "owner changed");
    }

    function testRemovedSelectorCanBeAddedAgain() public {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IBns.latestCheckpoint.selector;
        bns.removeFacet(selectors);

        (bool ok, bytes memory result) =
            address(bns).call(abi.encodeCall(IBns.latestCheckpoint, ()));
        assertTrue(!ok, "removed selector still callable");
        assertTrue(result.length >= 4, "missing router error");
        bytes4 errorSelector;
        assembly ("memory-safe") {
            errorSelector := mload(add(result, 32))
        }
        assertTrue(errorSelector == FacetSelectorNotAssigned.selector, "unexpected router error");

        FacetCut[] memory cuts = new FacetCut[](1);
        cuts[0] = FacetCut({ facet: address(new BnsResolverFacet()), selectors: selectors });
        bns.addFacets(cuts);
        bns.latestCheckpoint();
    }

    function testUnknownSelectorIsRejected() public {
        (bool ok, bytes memory result) = address(bns).call(hex"deadbeef");
        assertTrue(!ok, "unknown selector accepted");
        assertTrue(result.length >= 4, "missing router error");
    }
}
