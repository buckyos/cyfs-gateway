// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import { BnsCore } from "./BnsCore.sol";

contract BnsDocumentFacet is BnsCore {
    function setMinDocumentIat(
        string calldata name,
        uint64 minDocumentIat,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq, uint64 ownerPolicySeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        return _setMinDocumentIatInternal(nameHash, name, minDocumentIat, reasonHash, true);
    }

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
    ) external returns (uint64 version) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash,
            name,
            state,
            docType,
            PERMISSION_PUBLISH_DOCUMENT,
            OP_PUBLISH_DOCUMENT,
            authority,
            guard
        );
        return _publishDocumentInternal(
            nameHash,
            name,
            docType,
            expectedVersion,
            document,
            controller,
            beneficiary,
            paymentTarget,
            expireAt,
            controllerPolicyHash,
            paymentPolicyHash,
            splitPolicyHash,
            pricePolicyHash,
            rightsPolicyHash,
            true
        );
    }

    function revokeDocument(
        string calldata name,
        string calldata docType,
        uint64 expectedVersion,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 newVersion, uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash,
            name,
            state,
            docType,
            PERMISSION_REVOKE_DOCUMENT,
            OP_REVOKE_DOCUMENT,
            authority,
            guard
        );

        bytes32 stateKey = _lineageStateKey(nameHash);
        uint64 current = _currentDocumentVersions[stateKey][docTypeHash];
        if (current != expectedVersion) {
            revert StaleDocumentVersion(name, docType, expectedVersion, current);
        }

        uint64 nowTs = _now();
        newVersion = _currentDocumentVersions[nameHash][docTypeHash] + 1;
        _currentDocumentVersions[nameHash][docTypeHash] = newVersion;
        if (stateKey != nameHash) {
            _currentDocumentVersions[stateKey][docTypeHash] = newVersion;
        }

        DocumentState storage document = _documents[nameHash][docTypeHash][newVersion];
        document.name = name;
        document.docType = docType;
        document.version = newVersion;
        document.previousVersion = current;
        document.status = DocumentStatus.Revoked;
        document.validFrom = nowTs;
        document.expireAt = 0;
        document.revokedAt = nowTs;
        document.paymentTarget = address(0);
        document.controllerPolicyHash = bytes32(0);
        document.paymentPolicyHash = bytes32(0);
        document.splitPolicyHash = bytes32(0);
        document.pricePolicyHash = bytes32(0);
        document.rightsPolicyHash = bytes32(0);
        document.documentStateHash = _hashDocumentState(document);

        if (keccak256(bytes(docType)) == keccak256(bytes("owner"))) {
            state.ownerDocumentVersion = newVersion;
        }

        state.nameSeq += 1;
        state.updatedAt = nowTs;
        _commitEvent(
            EVENT_DOCUMENT_REVOKED,
            keccak256(abi.encode(nameHash, docTypeHash, current, newVersion, reasonHash))
        );
        emit DocumentRevoked(nameHash, name, docType, msg.sender, current, newVersion, reasonHash);
        return (newVersion, state.nameSeq);
    }

    function setControllerPolicy(
        string calldata name,
        ControllerRule[] calldata rules,
        bytes32 policyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        return _setControllerPolicyInternal(nameHash, name, rules, policyHash, true);
    }
}
