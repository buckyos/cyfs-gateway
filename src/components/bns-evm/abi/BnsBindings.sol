// SPDX-License-Identifier: MIT
// Generated from the aggregate BNS JSON ABI and Hardhat enum AST by
// src/apps/bns/hardhat-scripts/sync-abi.mjs. Do not edit.
pragma solidity ^0.8.24;

enum NameStatus {
    Available,
    Active,
    Expired,
    Released,
    Tombstoned
}

enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned
}

enum AliasKind {
    None,
    Alias,
    MigratedTo,
    Canonical
}

enum ReleaseMode {
    ReleaseAfterGrace,
    TombstoneForever
}

enum PrincipalKind {
    Unset,
    ChainAccount,
    BnsName
}

enum OwnerSource {
    None,
    AssetOwnerFallback,
    ExplicitSemanticOwner,
    ParentInherited
}

enum AuthorityRole {
    None,
    Owner,
    Controller
}

enum AuthorityKeyStatus {
    Missing,
    Active,
    Revoked,
    Expired
}

struct FacetCut {
    address facet;
    bytes4[] selectors;
}

struct AuthorityKey {
    bytes32 kid;
    bytes32 verificationMethod;
    bytes keyData;
    uint32 purposes;
    uint64 validFrom;
    uint64 validUntil;
    AuthorityKeyStatus status;
    bytes32 metadataHash;
}

struct AuthorityKeyUpdate {
    AuthorityKey key;
    bool active;
}

struct DocumentRef {
    bytes32 storageType;
    string uri;
    bytes inlineDocument;
    bytes32 contentHash;
    bytes32 schema;
    bytes32 codec;
    bytes32 extraHash;
}

struct Principal {
    PrincipalKind kind;
    bytes value;
}

struct DocumentUpdate {
    string docType;
    uint64 expectedVersion;
    DocumentRef document;
    Principal controller;
    Principal beneficiary;
    address paymentTarget;
    uint64 expireAt;
    bytes32 controllerPolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
}

struct OwnerPolicyUpdate {
    bool updateMinDocumentIat;
    uint64 minDocumentIat;
    bytes32 reasonHash;
}

struct CallAuthority {
    AuthorityRole role;
    Principal actor;
    bytes32 kid;
}

struct MutationGuard {
    uint64 expectedNameSeq;
    uint64 expectedParentNameSeq;
}

struct AliasState {
    string name;
    AliasKind kind;
    string targetDid;
    bytes32 proofHash;
    uint64 setAt;
    uint64 nameSeq;
}

struct AuthoritySetState {
    string name;
    uint64 authoritySeq;
    bytes32 authorityRoot;
    uint32 activeKeyCount;
}

struct DocumentState {
    string name;
    string docType;
    uint64 version;
    uint64 previousVersion;
    DocumentStatus status;
    DocumentRef document;
    Principal controller;
    Principal beneficiary;
    address paymentTarget;
    uint64 validFrom;
    uint64 expireAt;
    uint64 revokedAt;
    bytes32 controllerPolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
    bytes32 documentStateHash;
}

struct PurchaseContext {
    string name;
    string docType;
    uint64 documentVersion;
    Principal beneficiary;
    address paymentTarget;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
    DocumentStatus status;
    bytes32 proofRoot;
}

struct LogCheckpoint {
    bytes32 logRoot;
    uint64 lastSeq;
    uint64 issuedAt;
    Principal issuer;
    bytes32 externalAnchor;
}

struct NameState {
    string name;
    address assetOwner;
    Principal semanticOwner;
    Principal effectiveOwner;
    OwnerSource ownerSource;
    bool standardTransferEnabled;
    NameStatus status;
    uint64 registeredAt;
    uint64 expireAt;
    uint64 graceUntil;
    uint64 updatedAt;
    uint64 nameSeq;
    uint64 ownerDocumentVersion;
    uint64 minDocumentIat;
    uint64 ownerPolicySeq;
    uint64 lineageEpoch;
    bool renewable;
    bool transferable;
    bool allowDelegatedSubnames;
    bytes32 namespacePolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 aliasStateHash;
}

struct RegisterOptions {
    uint64 duration;
    uint64 gracePeriod;
    bool renewable;
    bool transferable;
    Principal initialSemanticOwner;
    bool allowDelegatedSubnames;
    address initialPaymentTarget;
    bytes32 initialPaymentPolicyHash;
    bytes32 initialNamespacePolicyHash;
}

struct ControllerRule {
    Principal controller;
    string docType;
    uint32 permissions;
    bytes32 namespaceScopeHash;
    uint64 validFrom;
    uint64 validUntil;
    bytes32 constraintHash;
}

struct OwnerResolution {
    Principal effectiveOwner;
    OwnerSource source;
    bytes32 authorityRoot;
    uint64 authoritySeq;
}

struct ResolveResult {
    NameState nameState;
    DocumentState documentState;
    OwnerResolution owner;
    Principal effectiveController;
    DocumentStatus status;
    AliasKind aliasKind;
    string aliasTargetDid;
    bytes32 proofRoot;
}

interface Bns {
    error FacetHasNoCode(address facet);
    error FacetSelectorAlreadyAssigned(bytes4 selector, address facet);
    error FacetSelectorNotAssigned(bytes4 selector);
    error InvalidFacetSelector(bytes4 selector);
    error ProtectedFacetSelector(bytes4 selector);
    event AuthorityKeysUpdated(bytes32 indexed nameHash, string name, address indexed actor, uint64 authoritySeq, bytes32 authorityRoot);
    event ControllerPolicyUpdated(bytes32 indexed nameHash, string name, address indexed actor, bytes32 policyHash, uint64 nameSeq);
    event DidAliasSet(bytes32 indexed nameHash, string name, address indexed actor, string targetDid, AliasKind kind, bytes32 proofHash, uint64 nameSeq);
    event DocumentPublished(bytes32 indexed nameHash, string name, string docType, uint64 indexed version, address indexed actor, bytes32 contentHash, bytes32 documentStateHash);
    event DocumentRevoked(bytes32 indexed nameHash, string name, string docType, address indexed actor, uint64 previousVersion, uint64 newVersion, bytes32 reasonHash);
    event FacetSelectorAdded(bytes4 indexed selector, address indexed facet);
    event FacetSelectorRemoved(bytes4 indexed selector, address indexed previousFacet);
    event FacetSelectorReplaced(bytes4 indexed selector, address indexed previousFacet, address indexed facet);
    event LogCheckpointPublished(bytes32 indexed logRoot, address indexed actor, uint64 lastSeq, uint64 issuedAt, bytes32 externalAnchor);
    event NameAssetTransferred(bytes32 indexed nameHash, string name, address indexed oldAssetOwner, address indexed newAssetOwner, bool standardTransfer, uint64 nameSeq);
    event NameOwnerUpdated(bytes32 indexed nameHash, string name, address indexed actor, PrincipalKind ownerKind, bytes ownerValue, OwnerSource ownerSource, bool standardTransferEnabled, uint64 nameSeq);
    event NameRegistered(bytes32 indexed nameHash, string name, address indexed assetOwner, address indexed actor, uint64 expireAt, uint64 lineageEpoch, uint64 nameSeq);
    event NameReleased(bytes32 indexed nameHash, string name, address indexed actor, ReleaseMode mode, bytes32 reasonHash, uint64 nameSeq);
    event NameRenewed(bytes32 indexed nameHash, string name, address indexed actor, uint64 expireAt, uint64 nameSeq);
    event NamespacePolicyUpdated(bytes32 indexed nameHash, string name, address indexed actor, bool allowDelegatedSubnames, bytes32 namespacePolicyHash, uint64 nameSeq);
    event OwnerDocumentIatFloorUpdated(bytes32 indexed nameHash, string name, address indexed actor, uint64 previousMinDocumentIat, uint64 newMinDocumentIat, uint64 ownerPolicySeq, uint64 nameSeq, bytes32 reasonHash);
    event PaymentTargetUpdated(bytes32 indexed nameHash, string name, string docType, address indexed actor, address paymentTarget, bytes32 paymentPolicyHash, uint64 version);
    event ProtocolEvent(uint64 indexed seq, bytes32 indexed eventType, address indexed actor, bytes32 previousLogRoot, bytes32 logRoot);
    function KEY_PURPOSE_AUTHENTICATION() external view returns (uint32);
    function KEY_PURPOSE_RECOVERY() external view returns (uint32);
    function KEY_PURPOSE_SIGN_DOCUMENT() external view returns (uint32);
    function MAX_INLINE_DOCUMENT() external view returns (uint64);
    function MAX_MUTATION_BATCH_INLINE_DOCUMENTS() external view returns (uint256);
    function MAX_MUTATION_BATCH_ITEMS() external view returns (uint8);
    function MAX_OWNER_REF_DEPTH() external view returns (uint8);
    function PERMISSION_PUBLISH_DOCUMENT() external view returns (uint32);
    function PERMISSION_REVOKE_DOCUMENT() external view returns (uint32);
    function PERMISSION_SET_ALIAS() external view returns (uint32);
    function PERMISSION_SET_NAMESPACE() external view returns (uint32);
    function PERMISSION_SET_PAYMENT() external view returns (uint32);
    function STORAGE_INLINE() external view returns (bytes32);
    function UPGRADE_INTERFACE_VERSION() external view returns (string memory);
    function addFacets(FacetCut[] calldata cuts) external;
    function applyMutations(string calldata name, AuthorityKeyUpdate[] calldata authorityUpdates, DocumentUpdate[] calldata documents, OwnerPolicyUpdate calldata ownerPolicy, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot, uint64 ownerPolicySeq);
    function bnsNamePrincipal(string calldata name) external pure returns (Principal memory);
    function chainAccountPrincipal(address account) external pure returns (Principal memory);
    function currentLogRoot() external view returns (bytes32);
    function facetForSelector(bytes4 selector) external view returns (address);
    function getAlias(string calldata name) external view returns (AliasState memory state);
    function getAuthorityKey(string calldata name, bytes32 kid) external view returns (AuthorityKey memory);
    function getAuthoritySet(string calldata name) external view returns (AuthoritySetState memory state);
    function getDocumentVersion(string calldata name, string calldata docType, uint64 version) external view returns (DocumentState memory state);
    function getPurchaseContext(string calldata name, string calldata docType) external view returns (PurchaseContext memory context);
    function globalEventSeq() external view returns (uint64);
    function initialize(address upgradeAdmin) external;
    function isStandardTransferEnabled(string calldata name) external view returns (bool);
    function latestCheckpoint() external view returns (LogCheckpoint memory);
    function owner() external view returns (address);
    function proxiableUUID() external view returns (bytes32);
    function publishDocument(string calldata name, string calldata docType, uint64 expectedVersion, DocumentRef calldata document, Principal calldata controller, Principal calldata beneficiary, address paymentTarget, uint64 expireAt, bytes32 controllerPolicyHash, bytes32 paymentPolicyHash, bytes32 splitPolicyHash, bytes32 pricePolicyHash, bytes32 rightsPolicyHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 version);
    function publishLogCheckpoint(Principal calldata issuer, bytes32 externalAnchor) external returns (LogCheckpoint memory checkpoint);
    function queryNameState(string calldata name) external view returns (NameState memory state);
    function registerName(string calldata name, address assetOwner, RegisterOptions calldata options, AuthorityKeyUpdate[] calldata authorityUpdates, Principal calldata semanticOwnerAfterAuthority, ControllerRule[] calldata controllerPolicy, bytes32 controllerPolicyHash, DocumentUpdate[] calldata initialDocuments, CallAuthority calldata authority, MutationGuard calldata guard) external payable returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot);
    function releaseName(string calldata name, ReleaseMode mode, bytes32 reasonHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq);
    function removeFacet(bytes4[] calldata selectors) external;
    function renewName(string calldata name, uint64 duration) external payable returns (uint64 expireAt);
    function renounceOwnership() external;
    function replaceFacet(address facet, bytes4[] calldata selectors) external;
    function resolveDocument(string calldata name, string calldata docType) external view returns (ResolveResult memory result);
    function resolveOwner(string calldata name) external view returns (OwnerResolution memory);
    function resolvePaymentTarget(string calldata name, string calldata docType, uint64 version) external view returns (Principal memory beneficiary, address paymentTarget, bytes32 paymentPolicyHash, bytes32 splitPolicyHash, bytes32 pricePolicyHash, bytes32 rightsPolicyHash, bytes32 proofRoot);
    function revokeDocument(string calldata name, string calldata docType, uint64 expectedVersion, bytes32 reasonHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 newVersion, uint64 nameSeq);
    function setControllerPolicy(string calldata name, ControllerRule[] calldata rules, bytes32 policyHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq);
    function setDidAlias(string calldata name, string calldata targetDid, AliasKind kind, bytes32 proofHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq);
    function setMinDocumentIat(string calldata name, uint64 minDocumentIat, bytes32 reasonHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq, uint64 ownerPolicySeq);
    function setNameOwner(string calldata name, Principal calldata semanticOwner, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq);
    function setNamespacePolicy(string calldata name, bool allowDelegatedSubnames, bytes32 namespacePolicyHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq);
    function setPaymentTarget(string calldata name, string calldata docType, uint64 expectedVersion, address paymentTarget, Principal calldata beneficiary, bytes32 paymentPolicyHash, bytes32 splitPolicyHash, bytes32 pricePolicyHash, bytes32 rightsPolicyHash, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 version);
    function transferName(string calldata name, address newAssetOwner, Principal calldata newSemanticOwner, DocumentUpdate[] calldata atomicDocumentUpdates, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 nameSeq);
    function transferOwnership(address newOwner) external;
    function updateAuthorityKeys(string calldata name, AuthorityKeyUpdate[] calldata updates, CallAuthority calldata authority, MutationGuard calldata guard) external returns (uint64 authoritySeq, bytes32 authorityRoot);
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
    error AddressEmptyCode(address target);
    error ERC1967InvalidImplementation(address implementation);
    error ERC1967NonPayable();
    error FailedCall();
    error InvalidInitialization();
    error NotInitializing();
    error OwnableInvalidOwner(address owner);
    error OwnableUnauthorizedAccount(address account);
    error UUPSUnauthorizedCallContext();
    error UUPSUnsupportedProxiableUUID(bytes32 slot);
    event Initialized(uint64 version);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Upgraded(address indexed implementation);
    error DocumentNotFound(string name, string docType);
    error InvalidDocType(string docType);
    error InvalidName(string name);
    error NameNotFound(string name);
    error NoConcreteSigner();
    error OwnerGraphTooDeep(uint256 maxDepth);
    error InlineDocumentTooLarge(uint256 len, uint256 max);
    error InvalidKid(bytes32 kid);
    error InvalidMutation(bytes32 reason);
    error InvalidPrincipal();
    error NameAlreadyExists(string name);
    error NotEffectiveOwner(string name);
    error OwnerGraphCycle();
    error StaleDocumentVersion(string name, string docType, uint64 expected, uint64 actual);
    error StaleParentNameSeq(string name, uint64 expected, uint64 actual);
    error ControllerScopeDenied(string name, string docType, bytes32 operation);
    error StaleNameSeq(string name, uint64 expected, uint64 actual);
}
