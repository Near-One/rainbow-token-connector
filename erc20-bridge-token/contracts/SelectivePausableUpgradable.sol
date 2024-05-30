// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract SelectivePausableUpgradable is Initializable, ContextUpgradeable {
    struct SelectivePausableStorage {
        uint _pausedFlags;
    }

    // keccak256(abi.encode(uint256(keccak256("aurora.SelectivePausable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SelectivePausableStorageLocation =
        0x3385e98de875c27690676838324244576ee92c4384629b3b7dd9c0a7c978e200;

    function _getSelectivePausableStorage()
        private
        pure
        returns (SelectivePausableStorage storage $)
    {
        assembly {
            $.slot := SelectivePausableStorageLocation
        }
    }

    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account, uint flags);

    /**
     * @dev Initializes the contract in unpaused state.
     */
    function __Pausable_init() internal onlyInitializing {
        __Pausable_init_unchained();
    }

    function __Pausable_init_unchained() internal onlyInitializing {
        SelectivePausableStorage storage $ = _getSelectivePausableStorage();
        $._pausedFlags = 0;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused(uint flag) {
        _requireNotPaused(flag);
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused(uint flag) {
        _requirePaused(flag);
        _;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused(uint flag) public view virtual returns (bool) {
        SelectivePausableStorage storage $ = _getSelectivePausableStorage();
        return ($._pausedFlags & flag) != 0;
    }

    /**
     * @dev Returns paused flags.
     */
    function pausedFlags() public view virtual returns (uint) {
        SelectivePausableStorage storage $ = _getSelectivePausableStorage();
        return $._pausedFlags;
    }

    /**
     * @dev Throws if the contract is paused.
     */
    function _requireNotPaused(uint flag) internal view virtual {
        require(!paused(flag), "Pausable: paused");
    }

    /**
     * @dev Throws if the contract is not paused.
     */
    function _requirePaused(uint flag) internal view virtual {
        require(paused(flag), "Pausable: not paused");
    }

    /**
     * @dev Triggers stopped state.
     */
    function _pause(uint flags) internal virtual {
        SelectivePausableStorage storage $ = _getSelectivePausableStorage();
        $._pausedFlags = flags;
        emit Paused(_msgSender(), $._pausedFlags);
    }
}
