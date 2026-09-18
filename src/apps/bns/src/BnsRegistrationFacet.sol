// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import { BnsCore } from "./BnsCore.sol";

contract BnsRegistrationFacet is BnsCore {
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
        returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot)
    {
        _validateBatchBounds(authorityUpdates.length, initialDocuments);
        _validateUniqueDocumentTypes(initialDocuments);
        bytes32 nameHash =
            _registerNameHash(name, assetOwner, options, initialDocuments, authority, guard);

        if (authorityUpdates.length != 0) {
            AuthoritySetState memory set = _applyAuthorityUpdates(nameHash, name, authorityUpdates);
            authoritySeq = set.authoritySeq;
            authorityRoot = set.authorityRoot;
        }

        _validateSemanticOwnerCalldata(semanticOwnerAfterAuthority);
        if (semanticOwnerAfterAuthority.kind != PrincipalKind.Unset) {
            _requireActiveAuthoritySetForPrincipal(semanticOwnerAfterAuthority);
            NameState storage state = _names[nameHash];
            _copyPrincipal(state.semanticOwner, semanticOwnerAfterAuthority);
            state.updatedAt = _now();
            _validateAllOwnerGraphs();
            NameState memory materialized = _materializeNameState(state);
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
        }

        if (controllerPolicy.length != 0 || controllerPolicyHash != bytes32(0)) {
            _setControllerPolicyInternal(nameHash, name, controllerPolicy, controllerPolicyHash, false);
        }

        NameState storage latest = _names[nameHash];
        AuthoritySetState memory finalSet = _authoritySets[_lineageStateKey(nameHash)];
        return (latest.nameSeq, finalSet.authoritySeq, finalSet.authorityRoot);
    }
}
