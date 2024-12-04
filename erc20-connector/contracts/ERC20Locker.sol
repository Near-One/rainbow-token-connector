// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.11;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "rainbow-bridge-sol/nearbridge/contracts/AdminControlled.sol";
import "rainbow-bridge-sol/nearprover/contracts/ProofDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/Borsh.sol";
import "./Locker.sol";

contract ERC20Locker is Locker, AdminControlled {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;
    using Borsh for Borsh.Data;

    event Locked (
        address indexed token,
        address indexed sender,
        uint256 amount,
        string accountId
    );

    event Unlocked (
        uint128 amount,
        address recipient
    );

    // Function output from burning fungible token on Near side.
    struct BurnResult {
        uint128 amount;
        address token;
        address recipient;
    }

    uint constant UNPAUSED_ALL = 0;
    uint constant PAUSED_LOCK = 1 << 0;
    uint constant PAUSED_UNLOCK = 1 << 1;

    // ERC20Locker is linked to the bridge token factory on NEAR side.
    // It also links to the prover that it uses to unlock the tokens.
    constructor(bytes memory _nearTokenFactory,
                INearProver _prover,
                uint64 _minBlockAcceptanceHeight,
                address _admin,
                uint _pausedFlags)
        AdminControlled(_admin, _pausedFlags)
        Locker(_nearTokenFactory, _prover, _minBlockAcceptanceHeight)
    {
    }

    function lockToken(address ethToken, uint256 amount, string memory accountId)
        public
        pausable (PAUSED_LOCK)
    {
        require(IERC20(ethToken).balanceOf(address(this)).add(amount) <= ((uint256(1) << 128) - 1), "Maximum tokens locked exceeded (< 2^128 - 1)");
        IERC20(ethToken).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(address(ethToken), msg.sender, amount, accountId);
    }

    function unlockToken(bytes memory proofData, uint64 proofBlockHeight)
        public
        pausable (PAUSED_UNLOCK)
    {
        ProofDecoder.ExecutionStatus memory status = _parseAndConsumeProof(proofData, proofBlockHeight);
        BurnResult memory result = _decodeBurnResult(status.successValue);
        IERC20(result.token).safeTransfer(result.recipient, result.amount);
        emit Unlocked(result.amount, result.recipient);
    }

    function _decodeBurnResult(bytes memory data) internal pure returns(BurnResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        uint8 flag = borshData.decodeU8();
        require(flag == 0, "ERR_NOT_WITHDRAW_RESULT");
        result.amount = borshData.decodeU128();
        bytes20 token = borshData.decodeBytes20();
        result.token = address(uint160(token));
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
        borshData.done();
    }

    // tokenFallback implements the ContractReceiver interface from ERC223-token-standard.
    // This allows to support ERC223 tokens with no extra cost.
    // The function always passes: we don't need to make any decision and the contract always
    // accept token transfers transfer.
    function tokenFallback(address _from, uint _value, bytes memory _data) public pure {}

    function adminTransfer(IERC20 token, address destination, uint amount)
        public
        onlyAdmin
    {
        token.safeTransfer(destination, amount);
    }
}
