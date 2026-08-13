// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";

interface IBnsEvents {
    event ProtocolEvent(
        uint64 indexed seq,
        bytes32 indexed eventType,
        address indexed actor,
        bytes32 previousLogRoot,
        bytes32 logRoot
    );

    event NameRegistered(
        bytes32 indexed nameHash,
        string name,
        address indexed assetOwner,
        address indexed actor,
        uint64 expireAt,
        uint64 lineageEpoch,
        uint64 nameSeq
    );

    event NameRenewed(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        uint64 expireAt,
        uint64 nameSeq
    );

    event NameAssetTransferred(
        bytes32 indexed nameHash,
        string name,
        address indexed oldAssetOwner,
        address indexed newAssetOwner,
        bool standardTransfer,
        uint64 nameSeq
    );

    event NameOwnerUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        PrincipalKind ownerKind,
        bytes ownerValue,
        OwnerSource ownerSource,
        bool standardTransferEnabled,
        uint64 nameSeq
    );

    event AuthorityKeysUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        uint64 authoritySeq,
        bytes32 authorityRoot
    );

    event NameReleased(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        ReleaseMode mode,
        bytes32 reasonHash,
        uint64 nameSeq
    );

    event DocumentPublished(
        bytes32 indexed nameHash,
        string name,
        string docType,
        uint64 indexed version,
        address indexed actor,
        bytes32 contentHash,
        bytes32 documentStateHash
    );

    event DocumentRevoked(
        bytes32 indexed nameHash,
        string name,
        string docType,
        address indexed actor,
        uint64 previousVersion,
        uint64 newVersion,
        bytes32 reasonHash
    );

    event OwnerDocumentIatFloorUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        uint64 previousMinDocumentIat,
        uint64 newMinDocumentIat,
        uint64 ownerPolicySeq,
        uint64 nameSeq,
        bytes32 reasonHash
    );

    event ControllerPolicyUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        bytes32 policyHash,
        uint64 nameSeq
    );

    event NamespacePolicyUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        bool allowDelegatedSubnames,
        bytes32 namespacePolicyHash,
        uint64 nameSeq
    );

    event DidAliasSet(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        string targetDid,
        AliasKind kind,
        bytes32 proofHash,
        uint64 nameSeq
    );

    event PaymentTargetUpdated(
        bytes32 indexed nameHash,
        string name,
        string docType,
        address indexed actor,
        address paymentTarget,
        bytes32 paymentPolicyHash,
        uint64 version
    );

    event LogCheckpointPublished(
        bytes32 indexed logRoot,
        address indexed actor,
        uint64 lastSeq,
        uint64 issuedAt,
        bytes32 externalAnchor
    );
}
