// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';

contract BridgeToken is
    Initializable,
    UUPSUpgradeable,
    ERC20Upgradeable,
    OwnableUpgradeable
{
    string private _name;
    string private _symbol;
    uint8 private _decimals;

    uint64 private _metadataLastUpdated;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) external initializer {
        __ERC20_init(name_, symbol_);
        __UUPSUpgradeable_init();
        __Ownable_init(_msgSender());

        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
    }

    function setMetadata(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        uint64 blockHeight_
    ) external onlyOwner {
        _metadataLastUpdated = blockHeight_;
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
    }

    function mint(address beneficiary, uint256 amount)
        external
        onlyOwner
    {
        _mint(beneficiary, amount);
    }

    function burn(address act, uint256 amount)
        external
        onlyOwner
    {
        _burn(act, amount);
    }

    function name() public view virtual override returns (string memory) {
        return _name;
    }

    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    function metadataLastUpdated() external view virtual returns (uint64) {
        return _metadataLastUpdated;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}
}
