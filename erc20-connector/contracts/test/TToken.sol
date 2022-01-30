// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.6;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";


contract TToken is ERC20 {
    constructor() public ERC20("TestToken", "TT") {
        _mint(msg.sender, 1000000000);
    }

    function mint(address beneficiary, uint256 amount) public {
        _mint(beneficiary, amount);
    }
}
