// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import { BnsCore } from "./BnsCore.sol";

contract BnsAtomicMutationFacet is BnsCore {
    function transferName(
        string calldata name,
        address newAssetOwner,
        Principal calldata newSemanticOwner,
        DocumentUpdate[] calldata atomicDocumentUpdates,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        if (newAssetOwner == address(0)) {
            revert InvalidPrincipal();
        }
        bytes32 nameHash = _validateName(name);
        _validateSemanticOwnerCalldata(newSemanticOwner);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        _requireActiveAuthoritySetForPrincipal(newSemanticOwner);

        address oldAssetOwner = state.assetOwner;
        state.assetOwner = newAssetOwner;
        _copyPrincipal(state.semanticOwner, newSemanticOwner);
        state.nameSeq += 1;
        state.updatedAt = _now();
        _validateAllOwnerGraphs();

        NameState memory materialized = _materializeNameState(state);
        _commitEvent(
            EVENT_NAME_TRANSFERRED,
            keccak256(abi.encode(nameHash, oldAssetOwner, newAssetOwner, state.nameSeq))
        );
        emit NameAssetTransferred(nameHash, name, oldAssetOwner, newAssetOwner, false, state.nameSeq);

        _commitEvent(
            EVENT_NAME_OWNER_UPDATED,
            keccak256(
                abi.encode(
                    nameHash,
                    materialized.semanticOwner.kind,
                    materialized.semanticOwner.value,
                    materialized.ownerSource,
                    materialized.standardTransferEnabled,
                    materialized.nameSeq
                )
            )
        );
        emit NameOwnerUpdated(
            nameHash,
            name,
            msg.sender,
            materialized.semanticOwner.kind,
            materialized.semanticOwner.value,
            materialized.ownerSource,
            materialized.standardTransferEnabled,
            materialized.nameSeq
        );

        for (uint256 i = 0; i < atomicDocumentUpdates.length; i++) {
            _publishDocumentUpdateInternal(nameHash, name, atomicDocumentUpdates[i], false);
        }
        return state.nameSeq;
    }

    function applyMutations(
        string calldata name,
        AuthorityKeyUpdate[] calldata authorityUpdates,
        DocumentUpdate[] calldata documents,
        OwnerPolicyUpdate calldata ownerPolicy,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    )
        external
        returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot, uint64 ownerPolicySeq)
    {
        if (
            authorityUpdates.length == 0 && documents.length == 0
                && !ownerPolicy.updateMinDocumentIat
        ) {
            revert InvalidMutation(ERR_EMPTY_MUTATION_BATCH);
        }
        _validateBatchBounds(
            authorityUpdates.length + (ownerPolicy.updateMinDocumentIat ? 1 : 0), documents
        );
        _validateUniqueDocumentTypes(documents);

        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);

        bool ownerOnly = authorityUpdates.length != 0 || ownerPolicy.updateMinDocumentIat
            || _containsOwnerDocument(documents);
        if (ownerOnly) {
            _authorizeOwner(nameHash, name, state, authority);
        } else {
            for (uint256 i = 0; i < documents.length; i++) {
                _authorizeUpdateNoGuard(
                    nameHash,
                    name,
                    state,
                    documents[i].docType,
                    PERMISSION_PUBLISH_DOCUMENT,
                    OP_PUBLISH_DOCUMENT,
                    authority
                );
            }
        }

        if (authorityUpdates.length != 0) {
            _applyAuthorityUpdates(nameHash, name, authorityUpdates);
        }
        if (documents.length != 0 || ownerPolicy.updateMinDocumentIat) {
            state.nameSeq += 1;
            state.updatedAt = _now();
        }
        if (documents.length != 0) {
            for (uint256 i = 0; i < documents.length; i++) {
                _publishDocumentUpdateInternal(nameHash, name, documents[i], false);
            }
        }
        if (ownerPolicy.updateMinDocumentIat) {
            _setMinDocumentIatInternal(
                nameHash, name, ownerPolicy.minDocumentIat, ownerPolicy.reasonHash, false
            );
        }

        AuthoritySetState memory finalSet = _authoritySets[nameHash];
        return (state.nameSeq, finalSet.authoritySeq, finalSet.authorityRoot, state.ownerPolicySeq);
    }
}
