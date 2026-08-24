// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import { BnsCore } from "./BnsCore.sol";

contract BnsAliasPaymentFacet is BnsCore {
    function setDidAlias(
        string calldata name,
        string calldata targetDid,
        AliasKind kind,
        bytes32 proofHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        if (kind != AliasKind.None) {
            _validateDid(targetDid);
        }
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash, name, state, "", PERMISSION_SET_ALIAS, OP_SET_ALIAS, authority, guard
        );

        state.nameSeq += 1;
        state.aliasStateHash = proofHash;
        state.updatedAt = _now();

        AliasState storage aliasState = _aliases[_lineageStateKey(nameHash)];
        aliasState.name = name;
        aliasState.kind = kind;
        aliasState.targetDid = targetDid;
        aliasState.proofHash = proofHash;
        aliasState.setAt = state.updatedAt;
        aliasState.nameSeq = state.nameSeq;

        _commitEvent(EVENT_DID_ALIAS, keccak256(abi.encode(nameHash, targetDid, kind, proofHash, state.nameSeq)));
        emit DidAliasSet(nameHash, name, msg.sender, targetDid, kind, proofHash, state.nameSeq);
        return state.nameSeq;
    }

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
    ) external returns (uint64 version) {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        _validatePrincipalCalldata(beneficiary);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash,
            name,
            state,
            docType,
            PERMISSION_SET_PAYMENT,
            OP_SET_PAYMENT,
            authority,
            guard
        );

        uint64 current = _currentDocumentVersions[_lineageStateKey(nameHash)][docTypeHash];
        if (current != expectedVersion) {
            revert StaleDocumentVersion(name, docType, expectedVersion, current);
        }
        if (current == 0) {
            revert DocumentNotFound(name, docType);
        }

        DocumentState storage document = _documents[nameHash][docTypeHash][current];
        document.paymentTarget = paymentTarget;
        _copyPrincipal(document.beneficiary, beneficiary);
        document.paymentPolicyHash = paymentPolicyHash;
        document.splitPolicyHash = splitPolicyHash;
        document.pricePolicyHash = pricePolicyHash;
        document.rightsPolicyHash = rightsPolicyHash;
        document.documentStateHash = _hashDocumentState(document);

        state.paymentPolicyHash = paymentPolicyHash;
        state.nameSeq += 1;
        state.updatedAt = _now();

        _commitEvent(
            EVENT_PAYMENT_TARGET,
            keccak256(abi.encode(nameHash, docTypeHash, paymentTarget, paymentPolicyHash, current))
        );
        emit PaymentTargetUpdated(
            nameHash, name, docType, msg.sender, paymentTarget, paymentPolicyHash, current
        );
        return current;
    }

    function publishLogCheckpoint(Principal calldata issuer, bytes32 externalAnchor)
        external
        returns (LogCheckpoint memory checkpoint)
    {
        _validatePrincipalCalldata(issuer);
        checkpoint.logRoot = currentLogRoot;
        checkpoint.lastSeq = globalEventSeq;
        checkpoint.issuedAt = _now();
        _copyPrincipal(_latestCheckpoint.issuer, issuer);
        _latestCheckpoint.logRoot = checkpoint.logRoot;
        _latestCheckpoint.lastSeq = checkpoint.lastSeq;
        _latestCheckpoint.issuedAt = checkpoint.issuedAt;
        _latestCheckpoint.externalAnchor = externalAnchor;
        checkpoint.issuer = _latestCheckpoint.issuer;
        checkpoint.externalAnchor = externalAnchor;
        _commitEvent(
            EVENT_LOG_CHECKPOINT,
            keccak256(abi.encode(checkpoint.logRoot, checkpoint.lastSeq, checkpoint.issuedAt, externalAnchor))
        );
        emit LogCheckpointPublished(
            checkpoint.logRoot, msg.sender, checkpoint.lastSeq, checkpoint.issuedAt, externalAnchor
        );
    }
}
