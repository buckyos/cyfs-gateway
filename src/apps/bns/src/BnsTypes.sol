// SPDX-License-Identifier: MIT
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

struct Principal {
    PrincipalKind kind;
    bytes value;
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

struct AuthoritySetState {
    string name;
    uint64 authoritySeq;
    bytes32 authorityRoot;
    uint32 activeKeyCount;
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

struct ControllerRule {
    Principal controller;
    string docType;
    uint32 permissions;
    bytes32 namespaceScopeHash;
    uint64 validFrom;
    uint64 validUntil;
    bytes32 constraintHash;
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

struct AliasState {
    string name;
    AliasKind kind;
    string targetDid;
    bytes32 proofHash;
    uint64 setAt;
    uint64 nameSeq;
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

struct FacetCut {
    address facet;
    bytes4[] selectors;
}

error InvalidName(string name);
error InvalidDocType(string docType);
error InvalidPrincipal();
error InvalidKid(bytes32 kid);
error NameAlreadyExists(string name);
error NameNotFound(string name);
error DocumentNotFound(string name, string docType);
error StaleNameSeq(string name, uint64 expected, uint64 actual);
error StaleParentNameSeq(string name, uint64 expected, uint64 actual);
error StaleDocumentVersion(string name, string docType, uint64 expected, uint64 actual);
error NotEffectiveOwner(string name);
error ControllerScopeDenied(string name, string docType, bytes32 operation);
error StandardTransferDisabled(string name);
error OwnerGraphCycle();
error NoConcreteSigner();
error OwnerGraphTooDeep(uint256 maxDepth);
error InlineDocumentTooLarge(uint256 len, uint256 max);
error InvalidMutation(bytes32 reason);
