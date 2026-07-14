// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import { IBnsEvents } from "./BnsEvents.sol";

interface IBns is IBnsEvents {
    error FacetHasNoCode(address facet);
    error FacetSelectorAlreadyAssigned(bytes4 selector, address facet);
    error FacetSelectorNotAssigned(bytes4 selector);
    error InvalidFacetSelector(bytes4 selector);
    error ProtectedFacetSelector(bytes4 selector);

    event FacetSelectorAdded(bytes4 indexed selector, address indexed facet);
    event FacetSelectorReplaced(
        bytes4 indexed selector, address indexed previousFacet, address indexed facet
    );
    event FacetSelectorRemoved(bytes4 indexed selector, address indexed previousFacet);

    function MAX_INLINE_DOCUMENT() external view returns (uint64);
    function MAX_MUTATION_BATCH_ITEMS() external view returns (uint8);
    function MAX_MUTATION_BATCH_INLINE_DOCUMENTS() external view returns (uint256);
    function MAX_OWNER_REF_DEPTH() external view returns (uint8);
    function KEY_PURPOSE_AUTHENTICATION() external view returns (uint32);
    function KEY_PURPOSE_RECOVERY() external view returns (uint32);
    function KEY_PURPOSE_SIGN_DOCUMENT() external view returns (uint32);
    function PERMISSION_PUBLISH_DOCUMENT() external view returns (uint32);
    function PERMISSION_REVOKE_DOCUMENT() external view returns (uint32);
    function PERMISSION_SET_PAYMENT() external view returns (uint32);
    function PERMISSION_SET_ALIAS() external view returns (uint32);
    function PERMISSION_SET_NAMESPACE() external view returns (uint32);
    function STORAGE_INLINE() external view returns (bytes32);
    function globalEventSeq() external view returns (uint64);
    function currentLogRoot() external view returns (bytes32);

    function initialize(address upgradeAdmin) external;
    function owner() external view returns (address);
    function transferOwnership(address newOwner) external;
    function renounceOwnership() external;
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
    function proxiableUUID() external view returns (bytes32);
    function UPGRADE_INTERFACE_VERSION() external view returns (string memory);
    function addFacets(FacetCut[] calldata cuts) external;
    function replaceFacet(address facet, bytes4[] calldata selectors) external;
    function removeFacet(bytes4[] calldata selectors) external;
    function facetForSelector(bytes4 selector) external view returns (address);

    function chainAccountPrincipal(address account) external pure returns (Principal memory);

    function bnsNamePrincipal(string calldata name) external pure returns (Principal memory);

    function queryNameState(string calldata name) external view returns (NameState memory state);

    function resolveOwner(string calldata name) external view returns (OwnerResolution memory);

    function isStandardTransferEnabled(string calldata name) external view returns (bool);

    function getAuthoritySet(string calldata name)
        external
        view
        returns (AuthoritySetState memory state);

    function getAuthorityKey(string calldata name, bytes32 kid)
        external
        view
        returns (AuthorityKey memory);

    function resolveDocument(string calldata name, string calldata docType)
        external
        view
        returns (ResolveResult memory result);

    function getDocumentVersion(string calldata name, string calldata docType, uint64 version)
        external
        view
        returns (DocumentState memory state);

    function getAlias(string calldata name) external view returns (AliasState memory state);

    function getPurchaseContext(string calldata name, string calldata docType)
        external
        view
        returns (PurchaseContext memory context);

    function resolvePaymentTarget(string calldata name, string calldata docType, uint64 version)
        external
        view
        returns (
            Principal memory beneficiary,
            address paymentTarget,
            bytes32 paymentPolicyHash,
            bytes32 splitPolicyHash,
            bytes32 pricePolicyHash,
            bytes32 rightsPolicyHash,
            bytes32 proofRoot
        );

    function latestCheckpoint() external view returns (LogCheckpoint memory);

    function registerName(
        string calldata name,
        address assetOwner,
        RegisterOptions calldata options,
        AuthorityKeyUpdate[] calldata authorityUpdates,
        Principal calldata semanticOwnerAfterAuthority,
        ControllerRule[] calldata controllerPolicy,
        bytes32 controllerPolicyHash,
        DocumentUpdate[] calldata initialDocuments,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    )
        external
        payable
        returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot);

    function transferName(
        string calldata name,
        address newAssetOwner,
        Principal calldata newSemanticOwner,
        DocumentUpdate[] calldata atomicDocumentUpdates,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq);

    function applyMutations(
        string calldata name,
        AuthorityKeyUpdate[] calldata authorityUpdates,
        DocumentUpdate[] calldata documents,
        OwnerPolicyUpdate calldata ownerPolicy,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    )
        external
        returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot, uint64 ownerPolicySeq);

    function renewName(string calldata name, uint64 duration)
        external
        payable
        returns (uint64 expireAt);

    function setNameOwner(
        string calldata name,
        Principal calldata semanticOwner,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq);

    function releaseName(
        string calldata name,
        ReleaseMode mode,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq);

    function setNamespacePolicy(
        string calldata name,
        bool allowDelegatedSubnames,
        bytes32 namespacePolicyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq);

    function updateAuthorityKeys(
        string calldata name,
        AuthorityKeyUpdate[] calldata updates,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 authoritySeq, bytes32 authorityRoot);

    function setMinDocumentIat(
        string calldata name,
        uint64 minDocumentIat,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq, uint64 ownerPolicySeq);

    function publishDocument(
        string calldata name,
        string calldata docType,
        uint64 expectedVersion,
        DocumentRef calldata document,
        Principal calldata controller,
        Principal calldata beneficiary,
        address paymentTarget,
        uint64 expireAt,
        bytes32 controllerPolicyHash,
        bytes32 paymentPolicyHash,
        bytes32 splitPolicyHash,
        bytes32 pricePolicyHash,
        bytes32 rightsPolicyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 version);

    function revokeDocument(
        string calldata name,
        string calldata docType,
        uint64 expectedVersion,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 newVersion, uint64 nameSeq);

    function setControllerPolicy(
        string calldata name,
        ControllerRule[] calldata rules,
        bytes32 policyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq);

    function setDidAlias(
        string calldata name,
        string calldata targetDid,
        AliasKind kind,
        bytes32 proofHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq);

    function setPaymentTarget(
        string calldata name,
        string calldata docType,
        uint64 expectedVersion,
        address paymentTarget,
        Principal calldata beneficiary,
        bytes32 paymentPolicyHash,
        bytes32 splitPolicyHash,
        bytes32 pricePolicyHash,
        bytes32 rightsPolicyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 version);

    function publishLogCheckpoint(Principal calldata issuer, bytes32 externalAnchor)
        external
        returns (LogCheckpoint memory checkpoint);
}
