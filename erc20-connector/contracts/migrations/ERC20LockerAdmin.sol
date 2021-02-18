pragma solidity ^0.6;

import "../ERC20Locker.sol";

/**
 * @dev Admin commands for ERC20 Locker
 *
 * This command is a template to be used when ERC20Locker needs to be upgraded.
 * Create a function with all changes that need to be applied. The function should
 * not receive any parameter. Compile and deploy the contract. Supposse the address
 * of the contract is ADR.
 *
 * To apply the upgrade call `adminDelegatecall` in the token locker from the admin account.
 *
 * ```js
 * let data = web3.eth.abi.encodeFunctionSignature("upgrade()");
 * locker.adminDelegatecall(ADR, data);
 * ```
 */
contract ERC20LockerAdmin is ERC20Locker {
    constructor(INearProver prover) ERC20Locker("", prover, address(0)) public {}

    function upgrade() public returns(bool) {
        prover_ = INearProver(address(0));
        return true;
    }
}