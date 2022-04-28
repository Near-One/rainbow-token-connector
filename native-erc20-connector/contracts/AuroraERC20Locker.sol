// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "rainbow-bridge-sol/nearbridge/contracts/AdminControlled.sol";
import "./AccountIds.sol";

contract AuroraERC20Locker is AdminControlled, AccountIds {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    event Locked(
        address indexed token,
        address indexed sender,
        uint256 amount,
        string accountId
    );

    event Unlocked(uint128 amount, address recipient);

    struct LockEvent {
        uint256 index;
        address token;
        address sender;
        uint256 amount;
        string receipient;
    }

    uint256 constant UNPAUSED_ALL = 0;
    uint256 constant PAUSED_LOCK = 1 << 0;
    uint256 constant PAUSED_UNLOCK = 1 << 1;

    mapping(uint256 => LockEvent) public lockEvents;
    uint256 lastLockEventIndex;
    string public nearTokenFactory;

    // ERC20Locker is linked to the bridge token factory on NEAR side.
    constructor(
        string memory _nearTokenFactory,
        address _admin,
        uint256 _pausedFlags
    ) AdminControlled(_admin, _pausedFlags) {
        lastLockEventIndex = 0;
        nearTokenFactory = _nearTokenFactory;
    }

    function lockToken(
        address ethToken,
        uint256 amount,
        string memory recipient
    ) public pausable(PAUSED_LOCK) returns (string memory) {
        require(
            IERC20(ethToken).balanceOf(address(this)).add(amount) <=
                ((uint256(1) << 128) - 1),
            "Maximum tokens locked exceeded (< 2^128 - 1)"
        );

        IERC20(ethToken).safeTransferFrom(msg.sender, address(this), amount);
        lastLockEventIndex++;
        LockEvent memory locekEvent = LockEvent(
            lastLockEventIndex,
            ethToken,
            msg.sender,
            amount,
            recipient
        );
        lockEvents[lastLockEventIndex] = locekEvent;
        string memory args = string(
            abi.encodePacked(
                '{"token":"',
                Strings.toHexString(uint160(ethToken), 20),
                '","nonce":"',
                Strings.toString(lastLockEventIndex),
                '"}'
            )
        );

        emit Locked(address(ethToken), msg.sender, amount, recipient);
        return
            string(
                abi.encodePacked(
                    "promises:",
                    nearTokenFactory,
                    "#",
                    "deposit",
                    "#",
                    args,
                    "#",
                    "20000000000000"
                )
            );
    }

    function unlockToken(
        address token,
        uint256 amount,
        address recipient
    ) public pausable(PAUSED_UNLOCK) {
        require(
            compareStrings(predecessorAccountId(), nearTokenFactory),
            "Mismatch factory account"
        );
        IERC20(token).safeTransfer(recipient, amount);
    }

    function claim(address token, uint256 nonce)
        public
        returns (uint256 amount, string memory receipient)
    {
        require(
            compareStrings(predecessorAccountId(), nearTokenFactory),
            "Mismatch factory account"
        );
        LockEvent memory lockEvent = lockEvents[nonce];
        require(lockEvent.token == token, "Mismatch token address");
        amount = lockEvent.amount;
        receipient = lockEvent.receipient;
        delete lockEvents[nonce];
    }

    function getTokenMetadata(address token)
        public
        view
        returns (
            string memory name,
            string memory symbol,
            uint8 decimals
        )
    {
        name = ERC20(token).name();
        symbol = ERC20(token).symbol();
        decimals = ERC20(token).decimals();
    }

    // tokenFallback implements the ContractReceiver interface from ERC223-token-standard.
    // This allows to support ERC223 tokens with no extra cost.
    // The function always passes: we don't need to make any decision and the contract always
    // accept token transfers transfer.
    function tokenFallback(
        address _from,
        uint256 _value,
        bytes memory _data
    ) public pure {}

    function adminTransfer(
        IERC20 token,
        address destination,
        uint256 amount
    ) public onlyAdmin {
        token.safeTransfer(destination, amount);
    }

    function compareStrings(string memory a, string memory b)
        private
        pure
        returns (bool)
    {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
}
