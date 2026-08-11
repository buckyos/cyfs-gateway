// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { OwnableUpgradeable } from
    "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BnsCore } from "./BnsCore.sol";
import { FacetCut } from "./BnsTypes.sol";

error FacetHasNoCode(address facet);
error FacetSelectorAlreadyAssigned(bytes4 selector, address facet);
error FacetSelectorNotAssigned(bytes4 selector);
error InvalidFacetSelector(bytes4 selector);
error ProtectedFacetSelector(bytes4 selector);

library BnsRouterStorage {
    bytes32 internal constant SLOT = keccak256("buckyos.bns.router.storage.v1");

    struct Layout {
        mapping(bytes4 => address) facets;
    }

    function layout() internal pure returns (Layout storage state) {
        bytes32 slot = SLOT;
        assembly ("memory-safe") {
            state.slot := slot
        }
    }
}

/// UUPS implementation and selector router for the canonical BNS proxy.
/// Business functions execute in facets through delegatecall and therefore use
/// the proxy address, original msg.sender, and the BnsCore storage layout.
contract Bns is Initializable, OwnableUpgradeable, UUPSUpgradeable, BnsCore {
    event FacetSelectorAdded(bytes4 indexed selector, address indexed facet);
    event FacetSelectorReplaced(
        bytes4 indexed selector, address indexed previousFacet, address indexed facet
    );
    event FacetSelectorRemoved(bytes4 indexed selector, address indexed previousFacet);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// Initializes the proxy and assigns the account authorized to upgrade the
    /// UUPS router and manage its facet selector table.
    function initialize(address upgradeAdmin) external initializer {
        __Ownable_init(upgradeAdmin);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function addFacets(FacetCut[] calldata cuts) external onlyOwner {
        for (uint256 i = 0; i < cuts.length; i++) {
            _addFacet(cuts[i].facet, cuts[i].selectors);
        }
    }

    function replaceFacet(address facet, bytes4[] calldata selectors) external onlyOwner {
        _requireFacetCode(facet);
        BnsRouterStorage.Layout storage state = BnsRouterStorage.layout();
        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            _requireRoutableSelector(selector);
            address previousFacet = state.facets[selector];
            if (previousFacet == address(0)) {
                revert FacetSelectorNotAssigned(selector);
            }
            state.facets[selector] = facet;
            emit FacetSelectorReplaced(selector, previousFacet, facet);
        }
    }

    function removeFacet(bytes4[] calldata selectors) external onlyOwner {
        BnsRouterStorage.Layout storage state = BnsRouterStorage.layout();
        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            address previousFacet = state.facets[selector];
            if (previousFacet == address(0)) {
                revert FacetSelectorNotAssigned(selector);
            }
            delete state.facets[selector];
            emit FacetSelectorRemoved(selector, previousFacet);
        }
    }

    function facetForSelector(bytes4 selector) external view returns (address) {
        return BnsRouterStorage.layout().facets[selector];
    }

    function _addFacet(address facet, bytes4[] calldata selectors) internal {
        _requireFacetCode(facet);
        BnsRouterStorage.Layout storage state = BnsRouterStorage.layout();
        for (uint256 i = 0; i < selectors.length; i++) {
            bytes4 selector = selectors[i];
            _requireRoutableSelector(selector);
            address assignedFacet = state.facets[selector];
            if (assignedFacet != address(0)) {
                revert FacetSelectorAlreadyAssigned(selector, assignedFacet);
            }
            state.facets[selector] = facet;
            emit FacetSelectorAdded(selector, facet);
        }
    }

    function _requireFacetCode(address facet) internal view {
        if (facet == address(0) || facet.code.length == 0) {
            revert FacetHasNoCode(facet);
        }
    }

    function _requireRoutableSelector(bytes4 selector) internal pure {
        if (selector == bytes4(0)) {
            revert InvalidFacetSelector(selector);
        }
        if (_isProtectedSelector(selector)) {
            revert ProtectedFacetSelector(selector);
        }
    }

    function _isProtectedSelector(bytes4 selector) internal pure returns (bool) {
        return selector == bytes4(keccak256("initialize(address)"))
            || selector == bytes4(keccak256("owner()"))
            || selector == bytes4(keccak256("transferOwnership(address)"))
            || selector == bytes4(keccak256("renounceOwnership()"))
            || selector == bytes4(keccak256("upgradeToAndCall(address,bytes)"))
            || selector == bytes4(keccak256("proxiableUUID()"))
            || selector == bytes4(keccak256("UPGRADE_INTERFACE_VERSION()"))
            || selector == bytes4(keccak256("addFacets((address,bytes4[])[])"))
            || selector == bytes4(keccak256("replaceFacet(address,bytes4[])"))
            || selector == bytes4(keccak256("removeFacet(bytes4[])"))
            || selector == bytes4(keccak256("facetForSelector(bytes4)"))
            || selector == bytes4(keccak256("MAX_INLINE_DOCUMENT()"))
            || selector == bytes4(keccak256("MAX_MUTATION_BATCH_ITEMS()"))
            || selector == bytes4(keccak256("MAX_MUTATION_BATCH_INLINE_DOCUMENTS()"))
            || selector == bytes4(keccak256("MAX_OWNER_REF_DEPTH()"))
            || selector == bytes4(keccak256("KEY_PURPOSE_AUTHENTICATION()"))
            || selector == bytes4(keccak256("KEY_PURPOSE_RECOVERY()"))
            || selector == bytes4(keccak256("KEY_PURPOSE_SIGN_DOCUMENT()"))
            || selector == bytes4(keccak256("PERMISSION_PUBLISH_DOCUMENT()"))
            || selector == bytes4(keccak256("PERMISSION_REVOKE_DOCUMENT()"))
            || selector == bytes4(keccak256("PERMISSION_SET_PAYMENT()"))
            || selector == bytes4(keccak256("PERMISSION_SET_ALIAS()"))
            || selector == bytes4(keccak256("PERMISSION_SET_NAMESPACE()"))
            || selector == bytes4(keccak256("STORAGE_INLINE()"))
            || selector == bytes4(keccak256("globalEventSeq()"))
            || selector == bytes4(keccak256("currentLogRoot()"));
    }

    /// @custom:oz-upgrades-unsafe-allow delegatecall
    fallback() external payable {
        address facet = BnsRouterStorage.layout().facets[msg.sig];
        if (facet == address(0)) {
            revert FacetSelectorNotAssigned(msg.sig);
        }

        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch success
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {
        revert FacetSelectorNotAssigned(bytes4(0));
    }
}
