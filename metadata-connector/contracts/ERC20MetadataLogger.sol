// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.5;

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

/**
 * @title ERC20MetadataLogger
 * @dev emits and retreive ERC-20 metadata
 */
contract ERC20MetadataLogger {
    
    event Log(
            address indexed erc20,
            string name,
            string symbol,
            uint8 decimals
        );

    /**
     * @dev log values from the erc20 contract
     * @param erc20 contract address
     */
    function log(address erc20) external {
        IERC20Metadata _erc20 = IERC20Metadata(erc20);
        emit Log(
                erc20,
                _erc20.name(),
                _erc20.symbol(),
                _erc20.decimals()
            );
    }
}