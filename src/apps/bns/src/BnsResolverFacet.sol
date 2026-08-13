// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTypes.sol";
import { BnsCore } from "./BnsCore.sol";

contract BnsResolverFacet is BnsCore {
    function chainAccountPrincipal(address account) external pure returns (Principal memory) {
        return _chainAccountPrincipal(account);
    }

    function bnsNamePrincipal(string calldata name) external pure returns (Principal memory) {
        _validateName(name);
        return Principal({ kind: PrincipalKind.BnsName, value: bytes(name) });
    }

    function queryNameState(string calldata name) external view returns (NameState memory state) {
        bytes32 nameHash = _validateName(name);
        if (_names[nameHash].status == NameStatus.Available) {
            state.name = name;
            state.status = NameStatus.Available;
            return state;
        }
        return _materializeNameState(_names[nameHash]);
    }

    function resolveOwner(string calldata name) external view returns (OwnerResolution memory) {
        bytes32 nameHash = _validateName(name);
        _requireExistingName(nameHash, name);
        return _resolveOwner(nameHash, 0);
    }

    function isStandardTransferEnabled(string calldata name) external view returns (bool) {
        bytes32 nameHash = _validateName(name);
        _requireExistingName(nameHash, name);
        return _materializeNameState(_names[nameHash]).standardTransferEnabled;
    }

    function getAuthoritySet(string calldata name)
        external
        view
        returns (AuthoritySetState memory state)
    {
        bytes32 nameHash = _validateName(name);
        state = _authoritySets[nameHash];
        if (bytes(state.name).length == 0) {
            state.name = name;
        }
    }

    function getAuthorityKey(string calldata name, bytes32 kid)
        external
        view
        returns (AuthorityKey memory)
    {
        bytes32 nameHash = _validateName(name);
        return _authorityKeys[nameHash][kid];
    }

    function resolveDocument(string calldata name, string calldata docType)
        external
        view
        returns (ResolveResult memory result)
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        _requireExistingName(nameHash, name);

        result.nameState = _materializeNameState(_names[nameHash]);
        result.owner = _resolveOwner(nameHash, 0);
        uint64 version = _currentDocumentVersions[nameHash][docTypeHash];
        if (version == 0) {
            result.documentState.name = name;
            result.documentState.docType = docType;
            result.documentState.status = DocumentStatus.Missing;
            result.effectiveController = result.owner.effectiveOwner;
            result.status = DocumentStatus.Missing;
            result.proofRoot = currentLogRoot;
            return result;
        }

        result.documentState = _documents[nameHash][docTypeHash][version];
        result.effectiveController = result.documentState.controller.kind == PrincipalKind.Unset
            ? result.owner.effectiveOwner
            : result.documentState.controller;
        result.status = result.documentState.status;
        AliasState storage aliasState = _aliases[nameHash];
        result.aliasKind = aliasState.kind;
        result.aliasTargetDid = aliasState.targetDid;
        result.proofRoot = currentLogRoot;
    }

    function getDocumentVersion(string calldata name, string calldata docType, uint64 version)
        external
        view
        returns (DocumentState memory state)
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        state = _documents[nameHash][docTypeHash][version];
        if (state.version == 0) {
            state.name = name;
            state.docType = docType;
            state.version = version;
            state.status = DocumentStatus.Missing;
        }
    }

    function getAlias(string calldata name) external view returns (AliasState memory state) {
        bytes32 nameHash = _validateName(name);
        state = _aliases[nameHash];
        if (bytes(state.name).length == 0) {
            state.name = name;
        }
    }

    function getPurchaseContext(string calldata name, string calldata docType)
        external
        view
        returns (PurchaseContext memory context)
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        uint64 version = _currentDocumentVersions[nameHash][docTypeHash];
        if (version == 0) {
            revert DocumentNotFound(name, docType);
        }
        DocumentState storage document = _documents[nameHash][docTypeHash][version];
        context = PurchaseContext({
            name: name,
            docType: docType,
            documentVersion: document.version,
            beneficiary: document.beneficiary,
            paymentTarget: document.paymentTarget,
            paymentPolicyHash: document.paymentPolicyHash,
            splitPolicyHash: document.splitPolicyHash,
            pricePolicyHash: document.pricePolicyHash,
            rightsPolicyHash: document.rightsPolicyHash,
            status: document.status,
            proofRoot: currentLogRoot
        });
    }

    function resolvePaymentTarget(string calldata name, string calldata docType, uint64 version)
        external
        view
        returns (
            Principal memory beneficiary,
            address paymentTarget,
            bytes32 paymentPolicyHash,
            bytes32 splitPolicyHash,
            bytes32 pricePolicyHash,
            bytes32 rightsPolicyHash,
            bytes32 proofRoot
        )
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        DocumentState storage document = _documents[nameHash][docTypeHash][version];
        if (document.version == 0) {
            revert DocumentNotFound(name, docType);
        }
        return (
            document.beneficiary,
            document.paymentTarget,
            document.paymentPolicyHash,
            document.splitPolicyHash,
            document.pricePolicyHash,
            document.rightsPolicyHash,
            currentLogRoot
        );
    }

    function latestCheckpoint() external view returns (LogCheckpoint memory) {
        return _latestCheckpoint;
    }
}
