// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Named ERC-1967 proxy artifact for the UUPS-enabled BNS implementation.
contract BnsProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory initializationData)
        payable
        ERC1967Proxy(implementation, initializationData)
    {}
}
