// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import {IBnsEvents} from "./BnsEvents.sol";

abstract contract BnsCore is IBnsEvents {
    uint64 public constant MAX_INLINE_DOCUMENT = 4 * 1024;
    uint8 public constant MAX_MUTATION_BATCH_ITEMS = 32;
    uint256 public constant MAX_MUTATION_BATCH_INLINE_DOCUMENTS = 64 * 1024;
    uint8 public constant MAX_OWNER_REF_DEPTH = 8;

    uint32 public constant KEY_PURPOSE_AUTHENTICATION = 1 << 0;
    uint32 public constant KEY_PURPOSE_RECOVERY = 1 << 1;
    uint32 public constant KEY_PURPOSE_SIGN_DOCUMENT = 1 << 2;

    uint32 public constant PERMISSION_PUBLISH_DOCUMENT = 1 << 0;
    uint32 public constant PERMISSION_REVOKE_DOCUMENT = 1 << 1;
    uint32 public constant PERMISSION_SET_PAYMENT = 1 << 2;
    uint32 public constant PERMISSION_SET_ALIAS = 1 << 3;
    uint32 public constant PERMISSION_SET_NAMESPACE = 1 << 4;

    bytes32 public constant STORAGE_INLINE = 0x696e6c696e650000000000000000000000000000000000000000000000000000;
    bytes32 internal constant OP_PUBLISH_DOCUMENT = keccak256("publish_document");
    bytes32 internal constant OP_REVOKE_DOCUMENT = keccak256("revoke_document");
    bytes32 internal constant OP_SET_PAYMENT = keccak256("set_payment");
    bytes32 internal constant OP_SET_ALIAS = keccak256("set_alias");
    bytes32 internal constant OP_SET_NAMESPACE = keccak256("set_namespace");

    bytes32 internal constant LINEAGE_STATE_DOMAIN = keccak256("bns.lineage.state.v1");
    bytes32 internal constant LINEAGE_STATE_MARKER = keccak256("bns.lineage.state.marker.v1");

    bytes32 internal constant EVENT_NAME_REGISTERED = keccak256("name_registered");
    bytes32 internal constant EVENT_NAME_RENEWED = keccak256("name_renewed");
    bytes32 internal constant EVENT_NAME_TRANSFERRED = keccak256("name_asset_transferred");
    bytes32 internal constant EVENT_NAME_OWNER_UPDATED = keccak256("name_owner_updated");
    bytes32 internal constant EVENT_AUTHORITY_UPDATED = keccak256("authority_keys_updated");
    bytes32 internal constant EVENT_NAME_RELEASED = keccak256("name_released");
    bytes32 internal constant EVENT_DOCUMENT_PUBLISHED = keccak256("document_published");
    bytes32 internal constant EVENT_DOCUMENT_REVOKED = keccak256("document_revoked");
    bytes32 internal constant EVENT_OWNER_IAT_FLOOR_UPDATED = keccak256("owner_iat_floor_updated");
    bytes32 internal constant EVENT_CONTROLLER_POLICY = keccak256("controller_policy_updated");
    bytes32 internal constant EVENT_NAMESPACE_POLICY = keccak256("namespace_policy_updated");
    bytes32 internal constant EVENT_DID_ALIAS = keccak256("did_alias_set");
    bytes32 internal constant EVENT_PAYMENT_TARGET = keccak256("payment_target_updated");
    bytes32 internal constant EVENT_LOG_CHECKPOINT = keccak256("log_checkpoint_published");

    bytes32 internal constant ERR_BAD_DURATION = keccak256("BAD_DURATION");
    bytes32 internal constant ERR_NOT_RENEWABLE = keccak256("NOT_RENEWABLE");
    bytes32 internal constant ERR_ROOT_AUTHORITY_NOT_USED = keccak256("ROOT_AUTHORITY_NOT_USED");
    bytes32 internal constant ERR_EMPTY_STORAGE_TYPE = keccak256("EMPTY_STORAGE_TYPE");
    bytes32 internal constant ERR_INLINE_URI_NOT_EMPTY = keccak256("INLINE_URI_NOT_EMPTY");
    bytes32 internal constant ERR_BAD_CONTENT_HASH = keccak256("BAD_CONTENT_HASH");
    bytes32 internal constant ERR_NON_INLINE_HAS_BYTES = keccak256("NON_INLINE_HAS_BYTES");
    bytes32 internal constant ERR_INVALID_DID = keccak256("INVALID_DID");
    bytes32 internal constant ERR_EMPTY_MUTATION_BATCH = keccak256("EMPTY_MUTATION_BATCH");
    bytes32 internal constant ERR_MUTATION_BATCH_TOO_LARGE = keccak256("MUTATION_BATCH_TOO_LARGE");
    bytes32 internal constant ERR_BATCH_INLINE_TOO_LARGE = keccak256("BATCH_INLINE_TOO_LARGE");
    bytes32 internal constant ERR_DUPLICATE_DOC_TYPE = keccak256("DUPLICATE_DOC_TYPE");
    bytes32 internal constant ERR_MIN_DOCUMENT_IAT_REGRESSION = keccak256("MIN_DOCUMENT_IAT_REGRESSION");

    mapping(bytes32 => NameState) internal _names;
    mapping(bytes32 => bool) internal _knownNameHash;
    bytes32[] internal _nameHashes;

    mapping(bytes32 => AuthoritySetState) internal _authoritySets;
    mapping(bytes32 => mapping(bytes32 => AuthorityKey)) internal _authorityKeys;
    mapping(bytes32 => bytes32[]) internal _authorityKeyIds;
    mapping(bytes32 => mapping(bytes32 => bool)) internal _knownAuthorityKey;

    mapping(bytes32 => mapping(bytes32 => uint64)) internal _currentDocumentVersions;
    mapping(bytes32 => mapping(bytes32 => mapping(uint64 => DocumentState))) internal _documents;
    mapping(bytes32 => ControllerRule[]) internal _controllerPolicies;
    mapping(bytes32 => AliasState) internal _aliases;

    LogCheckpoint internal _latestCheckpoint;

    uint64 public globalEventSeq;
    bytes32 public currentLogRoot;

    // Existing fields must never be reordered. Add future fields immediately
    // before this gap and reduce its length by the slots they consume.
    uint256[50] internal __gap;

    function _registerNameHash(
        string calldata name,
        address assetOwner,
        RegisterOptions calldata options,
        DocumentUpdate[] calldata initialDocuments,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) internal returns (bytes32 nameHash) {
        if (assetOwner == address(0)) {
            revert InvalidPrincipal();
        }
        if (options.duration == 0) {
            revert InvalidMutation(ERR_BAD_DURATION);
        }
        nameHash = _validateName(name);
        _validateSemanticOwnerCalldata(options.initialSemanticOwner);
        _requireActiveAuthoritySetForPrincipal(options.initialSemanticOwner);

        NameState storage existing = _names[nameHash];
        if (
            existing.status == NameStatus.Active || existing.status == NameStatus.Expired
                || existing.status == NameStatus.Tombstoned
        ) {
            revert NameAlreadyExists(name);
        }

        string memory parent = _parentName(name);
        if (bytes(parent).length == 0) {
            if (authority.role != AuthorityRole.None) {
                revert InvalidMutation(ERR_ROOT_AUTHORITY_NOT_USED);
            }
        } else {
            bytes32 parentHash = _nameHash(parent);
            NameState storage parentState = _names[parentHash];
            _requireActiveName(parentHash, parent);
            if (parentState.nameSeq != guard.expectedParentNameSeq) {
                revert StaleParentNameSeq(parent, guard.expectedParentNameSeq, parentState.nameSeq);
            }
            _authorizeOwner(parentHash, parent, parentState, authority);
        }

        for (uint256 i = 0; i < initialDocuments.length; i++) {
            _validateDocType(initialDocuments[i].docType);
            if (initialDocuments[i].expectedVersion != 0) {
                revert StaleDocumentVersion(name, initialDocuments[i].docType, initialDocuments[i].expectedVersion, 0);
            }
            _validateDocumentRef(initialDocuments[i].document);
            _validatePrincipalCalldata(initialDocuments[i].controller);
            _validatePrincipalCalldata(initialDocuments[i].beneficiary);
        }

        if (!_knownNameHash[nameHash]) {
            _knownNameHash[nameHash] = true;
            _nameHashes.push(nameHash);
        }

        uint64 nowTs = _now();
        uint64 nextSeq = existing.nameSeq + 1;
        uint64 lineageEpoch = existing.nameSeq == 0 ? 0 : existing.lineageEpoch + 1;

        existing.name = name;
        existing.assetOwner = assetOwner;
        _copyPrincipal(existing.semanticOwner, options.initialSemanticOwner);
        delete existing.effectiveOwner;
        existing.ownerSource = OwnerSource.None;
        existing.standardTransferEnabled = false;
        existing.status = NameStatus.Active;
        existing.registeredAt = nowTs;
        existing.expireAt = nowTs + options.duration;
        existing.graceUntil = existing.expireAt + options.gracePeriod;
        existing.updatedAt = nowTs;
        existing.nameSeq = nextSeq;
        existing.ownerDocumentVersion = 0;
        existing.minDocumentIat = 0;
        existing.ownerPolicySeq = 0;
        existing.lineageEpoch = lineageEpoch;
        existing.renewable = options.renewable;
        existing.transferable = options.transferable;
        existing.allowDelegatedSubnames = options.allowDelegatedSubnames;
        existing.namespacePolicyHash = options.initialNamespacePolicyHash;
        existing.paymentPolicyHash = options.initialPaymentPolicyHash;
        existing.aliasStateHash = bytes32(0);

        _activateLineageState(nameHash, lineageEpoch);

        _validateAllOwnerGraphs();

        _commitEvent(
            EVENT_NAME_REGISTERED, keccak256(abi.encode(nameHash, assetOwner, existing.expireAt, lineageEpoch, nextSeq))
        );
        emit NameRegistered(nameHash, name, assetOwner, msg.sender, existing.expireAt, lineageEpoch, nextSeq);

        for (uint256 i = 0; i < initialDocuments.length; i++) {
            _publishDocumentUpdateInternal(nameHash, name, initialDocuments[i], false);
        }
    }

    function _publishDocumentUpdateInternal(
        bytes32 nameHash,
        string memory name,
        DocumentUpdate calldata update,
        bool bumpNameSeq
    ) internal returns (uint64) {
        return _publishDocumentInternal(
            nameHash,
            name,
            update.docType,
            update.expectedVersion,
            update.document,
            update.controller,
            update.beneficiary,
            update.paymentTarget,
            update.expireAt,
            update.controllerPolicyHash,
            update.paymentPolicyHash,
            update.splitPolicyHash,
            update.pricePolicyHash,
            update.rightsPolicyHash,
            bumpNameSeq
        );
    }

    function _publishDocumentInternal(
        bytes32 nameHash,
        string memory name,
        string calldata docType,
        uint64 expectedVersion,
        DocumentRef calldata documentRef,
        Principal calldata controller,
        Principal calldata beneficiary,
        address paymentTarget,
        uint64 expireAt,
        bytes32 controllerPolicyHash,
        bytes32 paymentPolicyHash,
        bytes32 splitPolicyHash,
        bytes32 pricePolicyHash,
        bytes32 rightsPolicyHash,
        bool bumpNameSeq
    ) internal returns (uint64 version) {
        bytes32 docTypeHash = _validateDocType(docType);
        _validateDocumentRef(documentRef);
        _validatePrincipalCalldata(controller);
        _validatePrincipalCalldata(beneficiary);

        bytes32 stateKey = _lineageStateKey(nameHash);
        uint64 actualVersion = _currentDocumentVersions[stateKey][docTypeHash];
        if (actualVersion != expectedVersion) {
            revert StaleDocumentVersion(name, docType, expectedVersion, actualVersion);
        }
        version = _currentDocumentVersions[nameHash][docTypeHash] + 1;
        _currentDocumentVersions[nameHash][docTypeHash] = version;
        if (stateKey != nameHash) {
            _currentDocumentVersions[stateKey][docTypeHash] = version;
        }

        DocumentState storage document = _documents[nameHash][docTypeHash][version];
        document.name = name;
        document.docType = docType;
        document.version = version;
        document.previousVersion = actualVersion;
        document.status = DocumentStatus.Active;
        _copyDocumentRef(document.document, documentRef);
        _copyPrincipal(document.controller, controller);
        _copyPrincipal(document.beneficiary, beneficiary);
        document.paymentTarget = paymentTarget;
        document.validFrom = _now();
        document.expireAt = expireAt;
        document.revokedAt = 0;
        document.controllerPolicyHash = controllerPolicyHash;
        document.paymentPolicyHash = paymentPolicyHash;
        document.splitPolicyHash = splitPolicyHash;
        document.pricePolicyHash = pricePolicyHash;
        document.rightsPolicyHash = rightsPolicyHash;
        document.documentStateHash = _hashDocumentState(document);

        NameState storage nameState = _names[nameHash];
        if (keccak256(bytes(docType)) == keccak256(bytes("owner"))) {
            nameState.ownerDocumentVersion = version;
        }
        if (bumpNameSeq) {
            nameState.nameSeq += 1;
        }
        nameState.updatedAt = _now();

        _commitEvent(
            EVENT_DOCUMENT_PUBLISHED,
            keccak256(abi.encode(nameHash, docTypeHash, version, documentRef.contentHash, document.documentStateHash))
        );
        emit DocumentPublished(
            nameHash, name, docType, version, msg.sender, documentRef.contentHash, document.documentStateHash
        );
    }

    function _setControllerPolicyInternal(
        bytes32 nameHash,
        string memory name,
        ControllerRule[] calldata rules,
        bytes32 policyHash,
        bool bumpNameSeq
    ) internal returns (uint64 nameSeq) {
        bytes32 stateKey = _lineageStateKey(nameHash);
        delete _controllerPolicies[stateKey];
        for (uint256 i = 0; i < rules.length; i++) {
            _validateControllerRule(rules[i]);
            if (rules[i].controller.kind == PrincipalKind.BnsName) {
                _requireActiveAuthoritySetForPrincipal(rules[i].controller);
            }
            _controllerPolicies[stateKey].push();
            ControllerRule storage stored = _controllerPolicies[stateKey][i];
            _copyPrincipal(stored.controller, rules[i].controller);
            stored.docType = rules[i].docType;
            stored.permissions = rules[i].permissions;
            stored.namespaceScopeHash = rules[i].namespaceScopeHash;
            stored.validFrom = rules[i].validFrom;
            stored.validUntil = rules[i].validUntil;
            stored.constraintHash = rules[i].constraintHash;
        }

        NameState storage state = _names[nameHash];
        if (bumpNameSeq) {
            state.nameSeq += 1;
        }
        state.updatedAt = _now();
        _commitEvent(EVENT_CONTROLLER_POLICY, keccak256(abi.encode(nameHash, policyHash, state.nameSeq)));
        emit ControllerPolicyUpdated(nameHash, name, msg.sender, policyHash, state.nameSeq);
        return state.nameSeq;
    }

    function _setMinDocumentIatInternal(
        bytes32 nameHash,
        string memory name,
        uint64 minDocumentIat,
        bytes32 reasonHash,
        bool bumpNameSeq
    ) internal returns (uint64 nameSeq, uint64 ownerPolicySeq) {
        NameState storage state = _names[nameHash];
        uint64 previous = state.minDocumentIat;
        if (minDocumentIat < previous) {
            revert InvalidMutation(ERR_MIN_DOCUMENT_IAT_REGRESSION);
        }

        if (bumpNameSeq) {
            state.nameSeq += 1;
        }
        state.minDocumentIat = minDocumentIat;
        state.ownerPolicySeq += 1;
        state.updatedAt = _now();

        _commitEvent(
            EVENT_OWNER_IAT_FLOOR_UPDATED,
            keccak256(abi.encode(nameHash, previous, minDocumentIat, state.ownerPolicySeq, state.nameSeq, reasonHash))
        );
        emit OwnerDocumentIatFloorUpdated(
            nameHash, name, msg.sender, previous, minDocumentIat, state.ownerPolicySeq, state.nameSeq, reasonHash
        );
        return (state.nameSeq, state.ownerPolicySeq);
    }

    function _applyAuthorityUpdates(bytes32 nameHash, string memory name, AuthorityKeyUpdate[] calldata updates)
        internal
        returns (AuthoritySetState memory set)
    {
        bytes32 stateKey = _lineageStateKey(nameHash);
        for (uint256 i = 0; i < updates.length; i++) {
            AuthorityKey calldata updateKey = updates[i].key;
            if (updateKey.kid == bytes32(0)) {
                revert InvalidKid(updateKey.kid);
            }
            if (updateKey.verificationMethod == bytes32(0)) {
                revert InvalidKid(updateKey.kid);
            }
            if (!_knownAuthorityKey[stateKey][updateKey.kid]) {
                _knownAuthorityKey[stateKey][updateKey.kid] = true;
                _authorityKeyIds[stateKey].push(updateKey.kid);
            }

            AuthorityKey storage stored = _authorityKeys[stateKey][updateKey.kid];
            stored.kid = updateKey.kid;
            stored.verificationMethod = updateKey.verificationMethod;
            stored.keyData = updateKey.keyData;
            stored.purposes = updateKey.purposes;
            stored.validFrom = updateKey.validFrom;
            stored.validUntil = updateKey.validUntil;
            stored.status = updates[i].active
                ? (updateKey.status == AuthorityKeyStatus.Missing ? AuthorityKeyStatus.Active : updateKey.status)
                : AuthorityKeyStatus.Revoked;
            stored.metadataHash = updateKey.metadataHash;
        }

        set = _recomputeAuthoritySet(nameHash, name);
        if (set.activeKeyCount == 0 && _nameIsAuthorityOwner(nameHash)) {
            revert NoConcreteSigner();
        }
        _authoritySets[stateKey] = set;
        _commitEvent(EVENT_AUTHORITY_UPDATED, keccak256(abi.encode(nameHash, set.authoritySeq, set.authorityRoot)));
        emit AuthorityKeysUpdated(nameHash, name, msg.sender, set.authoritySeq, set.authorityRoot);
    }

    function _recomputeAuthoritySet(bytes32 nameHash, string memory name)
        internal
        view
        returns (AuthoritySetState memory set)
    {
        bytes32 stateKey = _lineageStateKey(nameHash);
        bytes32 root = bytes32(0);
        uint32 activeCount = 0;
        bytes32[] storage ids = _authorityKeyIds[stateKey];
        uint64 nowTs = _now();
        for (uint256 i = 0; i < ids.length; i++) {
            AuthorityKey storage key = _authorityKeys[stateKey][ids[i]];
            root = keccak256(
                abi.encodePacked(
                    root,
                    key.kid,
                    key.verificationMethod,
                    keccak256(key.keyData),
                    key.purposes,
                    key.validFrom,
                    key.validUntil,
                    key.status,
                    key.metadataHash
                )
            );
            if (_isActiveKey(key, KEY_PURPOSE_AUTHENTICATION, nowTs)) {
                activeCount += 1;
            }
        }
        AuthoritySetState storage previous = _authoritySets[stateKey];
        set = AuthoritySetState({
            name: name, authoritySeq: previous.authoritySeq + 1, authorityRoot: root, activeKeyCount: activeCount
        });
    }

    function _authorizeUpdate(
        bytes32 nameHash,
        string memory name,
        NameState storage state,
        string memory docType,
        uint32 permission,
        bytes32 operation,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) internal view {
        _checkGuard(state, guard, name);
        _authorizeUpdateNoGuard(nameHash, name, state, docType, permission, operation, authority);
    }

    function _authorizeUpdateNoGuard(
        bytes32 nameHash,
        string memory name,
        NameState storage state,
        string memory docType,
        uint32 permission,
        bytes32 operation,
        CallAuthority calldata authority
    ) internal view {
        if (authority.role == AuthorityRole.Owner) {
            _authorizeOwner(nameHash, name, state, authority);
            return;
        }
        if (authority.role != AuthorityRole.Controller) {
            revert NotEffectiveOwner(name);
        }

        ControllerRule[] storage rules = _controllerPolicies[_lineageStateKey(nameHash)];
        for (uint256 i = 0; i < rules.length; i++) {
            ControllerRule storage rule = rules[i];
            if ((rule.permissions & permission) == 0) {
                continue;
            }
            if (!_docTypeMatches(rule.docType, docType)) {
                continue;
            }
            uint64 nowTs = _now();
            if (rule.validFrom > nowTs || (rule.validUntil != 0 && nowTs >= rule.validUntil)) {
                continue;
            }
            if (_authenticateExpectedPrincipal(rule.controller, authority, msg.sender)) {
                return;
            }
        }
        revert ControllerScopeDenied(name, docType, operation);
    }

    function _authorizeOwner(bytes32 nameHash, string memory name, NameState storage, CallAuthority calldata authority)
        internal
        view
    {
        if (authority.role != AuthorityRole.Owner) {
            revert NotEffectiveOwner(name);
        }
        OwnerResolution memory owner = _resolveOwner(nameHash, 0);
        if (!_authenticateExpectedPrincipal(owner.effectiveOwner, authority, msg.sender)) {
            revert NotEffectiveOwner(name);
        }
    }

    function _authenticateExpectedPrincipal(Principal memory expected, CallAuthority calldata authority, address signer)
        internal
        view
        returns (bool)
    {
        if (expected.kind == PrincipalKind.ChainAccount) {
            if (authority.actor.kind != PrincipalKind.ChainAccount) {
                return false;
            }
            (bool okExpected, address expectedAddress) = _tryAddressFromBytes(expected.value);
            (bool okActor, address actorAddress) = _tryAddressFromBytes(authority.actor.value);
            return okExpected && okActor && expectedAddress == signer && actorAddress == signer;
        }

        if (expected.kind == PrincipalKind.BnsName) {
            if (authority.actor.kind != PrincipalKind.BnsName) {
                return false;
            }
            if (keccak256(expected.value) != keccak256(authority.actor.value)) {
                return false;
            }
            bytes32 ownerHash = keccak256(expected.value);
            if (!_isActiveName(_names[ownerHash])) {
                return false;
            }
            return _authorityKeyAuthenticates(ownerHash, authority.kid, signer);
        }

        return false;
    }

    function _authorityKeyAuthenticates(bytes32 authorityNameHash, bytes32 kid, address signer)
        internal
        view
        returns (bool)
    {
        bytes32 stateKey = _lineageStateKey(authorityNameHash);
        AuthorityKey storage key = _authorityKeys[stateKey][kid];
        if (!_isActiveKey(key, KEY_PURPOSE_AUTHENTICATION, _now())) {
            return false;
        }
        (bool ok, address keyAddress) = _tryAddressFromBytes(key.keyData);
        return ok && keyAddress == signer;
    }

    function _resolveOwner(bytes32 nameHash, uint256 depth) internal view returns (OwnerResolution memory) {
        if (depth > MAX_OWNER_REF_DEPTH) {
            revert OwnerGraphTooDeep(MAX_OWNER_REF_DEPTH);
        }
        NameState storage state = _names[nameHash];
        if (state.status == NameStatus.Available) {
            revert NameNotFound(state.name);
        }

        if (state.semanticOwner.kind == PrincipalKind.BnsName) {
            string memory ownerName = string(state.semanticOwner.value);
            bytes32 ownerHash = _nameHash(ownerName);
            AuthoritySetState memory set = _authoritySets[_lineageStateKey(ownerHash)];
            if (_isActiveName(state)) {
                if (!_isActiveName(_names[ownerHash]) || set.activeKeyCount == 0) {
                    revert NoConcreteSigner();
                }
            }
            return OwnerResolution({
                effectiveOwner: state.semanticOwner,
                source: OwnerSource.ExplicitSemanticOwner,
                authorityRoot: set.authorityRoot,
                authoritySeq: set.authoritySeq
            });
        }

        string memory parent = _parentName(state.name);
        if (bytes(parent).length == 0) {
            AuthoritySetState memory set = _authoritySets[_lineageStateKey(nameHash)];
            return OwnerResolution({
                effectiveOwner: _chainAccountPrincipal(state.assetOwner),
                source: OwnerSource.AssetOwnerFallback,
                authorityRoot: set.authorityRoot,
                authoritySeq: set.authoritySeq
            });
        }

        bytes32 parentHash = _nameHash(parent);
        if (_isActiveName(state) && !_isActiveName(_names[parentHash])) {
            revert NoConcreteSigner();
        }
        OwnerResolution memory parentOwner = _resolveOwner(parentHash, depth + 1);
        parentOwner.source = OwnerSource.ParentInherited;
        return parentOwner;
    }

    function _materializeNameState(NameState storage stored) internal view returns (NameState memory state) {
        state = stored;
        state.status = _effectiveNameStatus(stored);
        OwnerResolution memory owner = _resolveOwner(_nameHash(stored.name), 0);
        state.effectiveOwner = owner.effectiveOwner;
        state.ownerSource = owner.source;
        state.standardTransferEnabled =
            stored.transferable && state.status == NameStatus.Active && owner.source == OwnerSource.AssetOwnerFallback;
    }

    function _checkGuard(NameState storage state, MutationGuard calldata guard, string memory name) internal view {
        if (state.nameSeq != guard.expectedNameSeq) {
            revert StaleNameSeq(name, guard.expectedNameSeq, state.nameSeq);
        }
    }

    function _validateAllOwnerGraphs() internal view {
        for (uint256 i = 0; i < _nameHashes.length; i++) {
            NameState storage state = _names[_nameHashes[i]];
            if (_isActiveName(state)) {
                _validateOwnerPath(_nameHashes[i]);
            }
        }
    }

    function _validateOwnerPath(bytes32 startHash) internal view {
        bytes32 current = startHash;
        bytes32[9] memory visited;
        for (uint256 depth = 0; depth <= MAX_OWNER_REF_DEPTH; depth++) {
            for (uint256 i = 0; i < depth; i++) {
                if (visited[i] == current) {
                    revert OwnerGraphCycle();
                }
            }
            visited[depth] = current;

            NameState storage state = _names[current];
            if (!_isActiveName(state)) {
                revert NoConcreteSigner();
            }

            if (state.semanticOwner.kind == PrincipalKind.BnsName) {
                bytes32 ownerHash = keccak256(state.semanticOwner.value);
                if (!_isActiveName(_names[ownerHash])) {
                    revert NoConcreteSigner();
                }
                AuthoritySetState storage set = _authoritySets[_lineageStateKey(ownerHash)];
                if (ownerHash == current) {
                    if (set.activeKeyCount == 0) {
                        revert NoConcreteSigner();
                    }
                    return;
                }
                if (set.activeKeyCount > 0) {
                    return;
                }
                current = ownerHash;
            } else {
                string memory parent = _parentName(state.name);
                if (bytes(parent).length == 0) {
                    if (state.assetOwner == address(0)) {
                        revert NoConcreteSigner();
                    }
                    return;
                }
                current = _nameHash(parent);
            }

            if (depth == MAX_OWNER_REF_DEPTH) {
                revert OwnerGraphTooDeep(MAX_OWNER_REF_DEPTH);
            }
        }
    }

    function _nameIsAuthorityOwner(bytes32 authorityNameHash) internal view returns (bool) {
        for (uint256 i = 0; i < _nameHashes.length; i++) {
            NameState storage state = _names[_nameHashes[i]];
            if (
                _isActiveName(state) && state.semanticOwner.kind == PrincipalKind.BnsName
                    && keccak256(state.semanticOwner.value) == authorityNameHash
            ) {
                return true;
            }
        }
        return false;
    }

    function _validateBatchBounds(uint256 authorityUpdateCount, DocumentUpdate[] calldata documents) internal pure {
        if (authorityUpdateCount + documents.length > MAX_MUTATION_BATCH_ITEMS) {
            revert InvalidMutation(ERR_MUTATION_BATCH_TOO_LARGE);
        }

        uint256 inlineBytes = 0;
        for (uint256 i = 0; i < documents.length; i++) {
            inlineBytes += documents[i].document.inlineDocument.length;
            if (inlineBytes > MAX_MUTATION_BATCH_INLINE_DOCUMENTS) {
                revert InvalidMutation(ERR_BATCH_INLINE_TOO_LARGE);
            }
        }
    }

    function _validateUniqueDocumentTypes(DocumentUpdate[] calldata documents) internal pure {
        bytes32[] memory seen = new bytes32[](documents.length);
        for (uint256 i = 0; i < documents.length; i++) {
            bytes32 docTypeHash = _validateDocType(documents[i].docType);
            for (uint256 j = 0; j < i; j++) {
                if (seen[j] == docTypeHash) {
                    revert InvalidMutation(ERR_DUPLICATE_DOC_TYPE);
                }
            }
            seen[i] = docTypeHash;
        }
    }

    function _containsOwnerDocument(DocumentUpdate[] calldata documents) internal pure returns (bool) {
        for (uint256 i = 0; i < documents.length; i++) {
            if (keccak256(bytes(documents[i].docType)) == keccak256(bytes("owner"))) {
                return true;
            }
        }
        return false;
    }

    function _validateDocumentRef(DocumentRef calldata documentRef) internal pure {
        if (documentRef.storageType == bytes32(0)) {
            revert InvalidMutation(ERR_EMPTY_STORAGE_TYPE);
        }
        if (documentRef.storageType == STORAGE_INLINE) {
            if (bytes(documentRef.uri).length != 0) {
                revert InvalidMutation(ERR_INLINE_URI_NOT_EMPTY);
            }
            uint256 len = documentRef.inlineDocument.length;
            if (len == 0 || len > MAX_INLINE_DOCUMENT) {
                revert InlineDocumentTooLarge(len, MAX_INLINE_DOCUMENT);
            }
            if (sha256(documentRef.inlineDocument) != documentRef.contentHash) {
                revert InvalidMutation(ERR_BAD_CONTENT_HASH);
            }
        } else if (documentRef.inlineDocument.length != 0) {
            revert InvalidMutation(ERR_NON_INLINE_HAS_BYTES);
        }
    }

    function _validateControllerRule(ControllerRule calldata rule) internal pure {
        _validatePrincipalCalldata(rule.controller);
        if (rule.controller.kind == PrincipalKind.Unset) {
            revert InvalidPrincipal();
        }
        if (bytes(rule.docType).length != 0) {
            _validateDocType(rule.docType);
        }
    }

    function _validateSemanticOwnerCalldata(Principal calldata principal) internal pure {
        if (principal.kind == PrincipalKind.Unset) {
            if (principal.value.length != 0) {
                revert InvalidPrincipal();
            }
            return;
        }
        if (principal.kind != PrincipalKind.BnsName) {
            revert InvalidPrincipal();
        }
        _validateName(string(principal.value));
    }

    function _validatePrincipalCalldata(Principal calldata principal) internal pure {
        if (principal.kind == PrincipalKind.Unset) {
            if (principal.value.length != 0) {
                revert InvalidPrincipal();
            }
        } else if (principal.kind == PrincipalKind.ChainAccount) {
            (bool ok, address account) = _tryAddressFromBytes(principal.value);
            if (!ok || account == address(0)) {
                revert InvalidPrincipal();
            }
        } else if (principal.kind == PrincipalKind.BnsName) {
            _validateName(string(principal.value));
        } else {
            revert InvalidPrincipal();
        }
    }

    function _requireActiveAuthoritySetForPrincipal(Principal calldata principal) internal view {
        if (principal.kind == PrincipalKind.BnsName) {
            bytes32 authorityNameHash = keccak256(principal.value);
            if (
                !_isActiveName(_names[authorityNameHash])
                    || _authoritySets[_lineageStateKey(authorityNameHash)].activeKeyCount == 0
            ) {
                revert NoConcreteSigner();
            }
        }
    }

    function _lineageStateKey(bytes32 nameHash) internal view returns (bytes32) {
        uint64 lineageEpoch = _names[nameHash].lineageEpoch;
        if (lineageEpoch == 0) {
            return nameHash;
        }

        bytes32 candidate = keccak256(abi.encode(LINEAGE_STATE_DOMAIN, nameHash, lineageEpoch));
        // A legacy implementation stored every lineage under nameHash. The marker
        // lets an upgraded contract keep serving such a live lineage until its
        // next registration creates an explicitly isolated state key.
        if (_currentDocumentVersions[candidate][LINEAGE_STATE_MARKER] != lineageEpoch) {
            return nameHash;
        }
        return candidate;
    }

    function _activateLineageState(bytes32 nameHash, uint64 lineageEpoch) internal {
        if (lineageEpoch == 0) {
            return;
        }
        bytes32 stateKey = keccak256(abi.encode(LINEAGE_STATE_DOMAIN, nameHash, lineageEpoch));
        _currentDocumentVersions[stateKey][LINEAGE_STATE_MARKER] = lineageEpoch;
    }

    function _requireExistingName(bytes32 nameHash, string memory name) internal view {
        if (_names[nameHash].status == NameStatus.Available) {
            revert NameNotFound(name);
        }
    }

    function _requireActiveName(bytes32 nameHash, string memory name) internal view {
        if (!_isActiveName(_names[nameHash])) {
            revert NameNotFound(name);
        }
    }

    function _effectiveNameStatus(NameState storage state) internal view returns (NameStatus) {
        if (state.status == NameStatus.Active && state.expireAt != 0 && _now() >= state.expireAt) {
            return NameStatus.Expired;
        }
        return state.status;
    }

    function _isActiveName(NameState storage state) internal view returns (bool) {
        return _effectiveNameStatus(state) == NameStatus.Active;
    }

    function _effectiveDocumentStatus(NameStatus nameStatus, DocumentStatus documentStatus, uint64 documentExpireAt)
        internal
        view
        returns (DocumentStatus)
    {
        if (nameStatus == NameStatus.Tombstoned) {
            return DocumentStatus.Tombstoned;
        }
        if (documentStatus != DocumentStatus.Active) {
            return documentStatus;
        }
        if (
            nameStatus == NameStatus.Expired || nameStatus == NameStatus.Released
                || (documentExpireAt != 0 && _now() >= documentExpireAt)
        ) {
            return DocumentStatus.Expired;
        }
        return DocumentStatus.Active;
    }

    function _isActiveKey(AuthorityKey storage key, uint32 purpose, uint64 nowTs) internal view returns (bool) {
        return key.status == AuthorityKeyStatus.Active && (key.purposes & purpose) != 0 && key.validFrom <= nowTs
            && (key.validUntil == 0 || nowTs < key.validUntil);
    }

    function _docTypeMatches(string storage ruleDocType, string memory docType) internal view returns (bool) {
        return bytes(ruleDocType).length == 0 || keccak256(bytes(ruleDocType)) == keccak256(bytes(docType));
    }

    function _validateName(string memory name) internal pure returns (bytes32) {
        bytes memory data = bytes(name);
        if (data.length == 0 || data.length > 253) {
            revert InvalidName(name);
        }

        uint256 dots = 0;
        uint256 labelStart = 0;
        for (uint256 i = 0; i < data.length; i++) {
            bytes1 c = data[i];
            if (c == ".") {
                if (i == labelStart || i - labelStart > 126 || data[i - 1] == "-") {
                    revert InvalidName(name);
                }
                dots += 1;
                if (dots > 1) {
                    revert InvalidName(name);
                }
                labelStart = i + 1;
                continue;
            }
            if (i == labelStart && c == "-") {
                revert InvalidName(name);
            }
            bool ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-";
            if (!ok) {
                revert InvalidName(name);
            }
        }
        if (data.length == labelStart || data.length - labelStart > 126 || data[data.length - 1] == "-") {
            revert InvalidName(name);
        }
        return keccak256(data);
    }

    function _validateDocType(string memory docType) internal pure returns (bytes32) {
        bytes memory data = bytes(docType);
        if (data.length == 0 || data.length > 32) {
            revert InvalidDocType(docType);
        }
        for (uint256 i = 0; i < data.length; i++) {
            bytes1 c = data[i];
            bool ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-" || c == "_";
            if (!ok) {
                revert InvalidDocType(docType);
            }
        }
        return keccak256(data);
    }

    function _validateDid(string memory did) internal pure {
        bytes memory data = bytes(did);
        if (data.length <= 4 || data[0] != "d" || data[1] != "i" || data[2] != "d" || data[3] != ":") {
            revert InvalidMutation(ERR_INVALID_DID);
        }
    }

    function _copyDocumentRef(DocumentRef storage target, DocumentRef calldata source) internal {
        target.storageType = source.storageType;
        target.uri = source.uri;
        target.inlineDocument = source.inlineDocument;
        target.contentHash = source.contentHash;
        target.schema = source.schema;
        target.codec = source.codec;
        target.extraHash = source.extraHash;
    }

    function _copyPrincipal(Principal storage target, Principal calldata source) internal {
        target.kind = source.kind;
        target.value = source.value;
    }

    function _hashDocumentState(DocumentState storage document) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                document.name,
                document.docType,
                document.version,
                document.previousVersion,
                document.status,
                document.document.storageType,
                document.document.uri,
                keccak256(document.document.inlineDocument),
                document.document.contentHash,
                document.document.schema,
                document.document.codec,
                document.document.extraHash,
                document.controller.kind,
                keccak256(document.controller.value),
                document.beneficiary.kind,
                keccak256(document.beneficiary.value),
                document.paymentTarget,
                document.validFrom,
                document.expireAt,
                document.revokedAt,
                document.controllerPolicyHash,
                document.paymentPolicyHash,
                document.splitPolicyHash,
                document.pricePolicyHash,
                document.rightsPolicyHash,
                block.chainid,
                address(this)
            )
        );
    }

    function _commitEvent(bytes32 eventType, bytes32 payloadHash) internal {
        bytes32 previous = currentLogRoot;
        globalEventSeq += 1;
        currentLogRoot =
            keccak256(abi.encodePacked(previous, block.chainid, address(this), globalEventSeq, eventType, payloadHash));
        emit ProtocolEvent(globalEventSeq, eventType, msg.sender, previous, currentLogRoot);
    }

    function _parentName(string memory name) internal pure returns (string memory) {
        bytes memory data = bytes(name);
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] == ".") {
                bytes memory parent = new bytes(data.length - i - 1);
                for (uint256 j = i + 1; j < data.length; j++) {
                    parent[j - i - 1] = data[j];
                }
                return string(parent);
            }
        }
        return "";
    }

    function _nameHash(string memory name) internal pure returns (bytes32) {
        return keccak256(bytes(name));
    }

    function _chainAccountPrincipal(address account) internal pure returns (Principal memory) {
        return Principal({kind: PrincipalKind.ChainAccount, value: abi.encodePacked(account)});
    }

    function _tryAddressFromBytes(bytes memory value) internal pure returns (bool, address account) {
        if (value.length == 20) {
            assembly ("memory-safe") {
                account := shr(96, mload(add(value, 32)))
            }
            return (true, account);
        }
        if (value.length == 32) {
            assembly ("memory-safe") {
                account := mload(add(value, 32))
            }
            return (true, account);
        }
        return (false, address(0));
    }

    function _now() internal view returns (uint64) {
        return uint64(block.timestamp);
    }
}
