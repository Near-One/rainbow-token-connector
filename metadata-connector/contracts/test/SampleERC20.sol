// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SampleERC20 is ERC20 {
    constructor() ERC20("SampleERC20", "ERC") {
        _mint(msg.sender, 10000);
    }
}