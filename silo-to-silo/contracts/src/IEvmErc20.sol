// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IEvmErc20 is IERC20 {
    function withdrawToNear(bytes memory recipient, uint256 amount) external;
}
