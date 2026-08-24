// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import {BnsCore} from "./BnsCore.sol";

contract BnsNameFacet is BnsCore {
    function renewName(string calldata name, uint64 duration) external payable returns (uint64 expireAt) {
        if (duration == 0) {
            revert InvalidMutation(ERR_BAD_DURATION);
        }
        bytes32 nameHash = _validateName(name);
        NameState storage state = _names[nameHash];
        _requireExistingName(nameHash, name);
        if (!state.renewable || state.status == NameStatus.Released || state.status == NameStatus.Tombstoned) {
            revert InvalidMutation(ERR_NOT_RENEWABLE);
        }

        uint64 nowTs = _now();
        uint64 graceDelta = state.graceUntil > state.expireAt ? state.graceUntil - state.expireAt : 0;
        uint64 base = state.expireAt > nowTs ? state.expireAt : nowTs;
        if (state.status == NameStatus.Expired) {
            state.status = NameStatus.Active;
        }
        state.expireAt = base + duration;
        state.graceUntil = state.expireAt + graceDelta;
        state.updatedAt = nowTs;
        state.nameSeq += 1;

        _commitEvent(EVENT_NAME_RENEWED, keccak256(abi.encode(nameHash, state.expireAt, state.nameSeq)));
        emit NameRenewed(nameHash, name, msg.sender, state.expireAt, state.nameSeq);
        return state.expireAt;
    }

    function setNameOwner(
        string calldata name,
        Principal calldata semanticOwner,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _validateSemanticOwnerCalldata(semanticOwner);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        _requireActiveAuthoritySetForPrincipal(semanticOwner);

        _copyPrincipal(state.semanticOwner, semanticOwner);
        state.nameSeq += 1;
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
        return state.nameSeq;
    }

    function releaseName(
        string calldata name,
        ReleaseMode mode,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);

        state.status = mode == ReleaseMode.TombstoneForever ? NameStatus.Tombstoned : NameStatus.Released;
        state.nameSeq += 1;
        state.updatedAt = _now();
        _commitEvent(EVENT_NAME_RELEASED, keccak256(abi.encode(nameHash, mode, reasonHash, state.nameSeq)));
        emit NameReleased(nameHash, name, msg.sender, mode, reasonHash, state.nameSeq);
        return state.nameSeq;
    }

    function setNamespacePolicy(
        string calldata name,
        bool allowDelegatedSubnames,
        bytes32 namespacePolicyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(nameHash, name, state, "", PERMISSION_SET_NAMESPACE, OP_SET_NAMESPACE, authority, guard);

        state.allowDelegatedSubnames = allowDelegatedSubnames;
        state.namespacePolicyHash = namespacePolicyHash;
        state.nameSeq += 1;
        state.updatedAt = _now();
        _commitEvent(
            EVENT_NAMESPACE_POLICY,
            keccak256(abi.encode(nameHash, allowDelegatedSubnames, namespacePolicyHash, state.nameSeq))
        );
        emit NamespacePolicyUpdated(
            nameHash, name, msg.sender, allowDelegatedSubnames, namespacePolicyHash, state.nameSeq
        );
        return state.nameSeq;
    }
}
