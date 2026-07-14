// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import { BnsCore } from "./BnsCore.sol";

contract BnsAuthorityFacet is BnsCore {
    function updateAuthorityKeys(
        string calldata name,
        AuthorityKeyUpdate[] calldata updates,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 authoritySeq, bytes32 authorityRoot) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        AuthoritySetState memory set = _applyAuthorityUpdates(nameHash, name, updates);
        return (set.authoritySeq, set.authorityRoot);
    }
}
