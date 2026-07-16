// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import { Bns } from "../src/Bns.sol";
import { BnsAliasPaymentFacet } from "../src/BnsAliasPaymentFacet.sol";
import { BnsAtomicMutationFacet } from "../src/BnsAtomicMutationFacet.sol";
import { BnsAuthorityFacet } from "../src/BnsAuthorityFacet.sol";
import { BnsDocumentFacet } from "../src/BnsDocumentFacet.sol";
import { BnsNameFacet } from "../src/BnsNameFacet.sol";
import { BnsRegistrationFacet } from "../src/BnsRegistrationFacet.sol";
import { BnsResolverFacet } from "../src/BnsResolverFacet.sol";
import { IBns } from "../src/IBns.sol";
import { FacetCut } from "../src/BnsTypes.sol";

abstract contract BnsTestDeployment {
    function _deployBnsProxy(address upgradeAdmin) internal returns (IBns instance) {
        Bns implementation = new Bns();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation), abi.encodeCall(Bns.initialize, (upgradeAdmin))
        );
        Bns router = Bns(payable(address(proxy)));
        FacetCut[] memory cuts = new FacetCut[](7);
        cuts[0] = FacetCut({
            facet: address(new BnsResolverFacet()),
            selectors: _resolverSelectors()
        });
        cuts[1] = FacetCut({
            facet: address(new BnsRegistrationFacet()),
            selectors: _registrationSelectors()
        });
        cuts[2] = FacetCut({
            facet: address(new BnsAtomicMutationFacet()),
            selectors: _atomicMutationSelectors()
        });
        cuts[3] = FacetCut({ facet: address(new BnsNameFacet()), selectors: _nameSelectors() });
        cuts[4] = FacetCut({
            facet: address(new BnsAuthorityFacet()),
            selectors: _authoritySelectors()
        });
        cuts[5] = FacetCut({
            facet: address(new BnsDocumentFacet()),
            selectors: _documentSelectors()
        });
        cuts[6] = FacetCut({
            facet: address(new BnsAliasPaymentFacet()),
            selectors: _aliasPaymentSelectors()
        });
        router.addFacets(cuts);
        return IBns(address(proxy));
    }

    function _resolverSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](13);
        selectors[0] = IBns.chainAccountPrincipal.selector;
        selectors[1] = IBns.bnsNamePrincipal.selector;
        selectors[2] = IBns.queryNameState.selector;
        selectors[3] = IBns.resolveOwner.selector;
        selectors[4] = IBns.isStandardTransferEnabled.selector;
        selectors[5] = IBns.getAuthoritySet.selector;
        selectors[6] = IBns.getAuthorityKey.selector;
        selectors[7] = IBns.resolveDocument.selector;
        selectors[8] = IBns.getDocumentVersion.selector;
        selectors[9] = IBns.getAlias.selector;
        selectors[10] = IBns.getPurchaseContext.selector;
        selectors[11] = IBns.resolvePaymentTarget.selector;
        selectors[12] = IBns.latestCheckpoint.selector;
    }

    function _registrationSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](1);
        selectors[0] = IBns.registerName.selector;
    }

    function _atomicMutationSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](2);
        selectors[0] = IBns.transferName.selector;
        selectors[1] = IBns.applyMutations.selector;
    }

    function _nameSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](4);
        selectors[0] = IBns.renewName.selector;
        selectors[1] = IBns.setNameOwner.selector;
        selectors[2] = IBns.releaseName.selector;
        selectors[3] = IBns.setNamespacePolicy.selector;
    }

    function _authoritySelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](1);
        selectors[0] = IBns.updateAuthorityKeys.selector;
    }

    function _documentSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](4);
        selectors[0] = IBns.setMinDocumentIat.selector;
        selectors[1] = IBns.publishDocument.selector;
        selectors[2] = IBns.revokeDocument.selector;
        selectors[3] = IBns.setControllerPolicy.selector;
    }

    function _aliasPaymentSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](3);
        selectors[0] = IBns.setDidAlias.selector;
        selectors[1] = IBns.setPaymentTarget.selector;
        selectors[2] = IBns.publishLogCheckpoint.selector;
    }
}
