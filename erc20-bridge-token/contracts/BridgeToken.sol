pragma solidity ^0.8;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";


contract BridgeToken is ERC20 {

    address private _controller; // has CONTROL role

    string private _name;
    string private _symbol;
    uint8 private _decimals;

    uint64 _metadataLastUpdated;

    constructor(
        string memory name_, 
        string memory symbol_,
        uint8 decimals_
    ) ERC20(name_, symbol_ ) {
        _controller = msg.sender;

        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
    }

    function set_metadata(
        string memory name_, 
        string memory symbol_,
        uint8 decimals_,
        uint64 blockHeight_
    ) public {
        require(msg.sender == _controller, "ERR_NOT_CONTROLLER");
        require(blockHeight_ >= _metadataLastUpdated, "ERR_OLD_METADATA");

        _metadataLastUpdated = blockHeight_;
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
    }

    function mint(address beneficiary, uint256 amount) public {
        require(msg.sender == _controller, "ERR_NOT_CONTROLLER");
        _mint(beneficiary, amount);
    }

    function burn(address act, uint256 amount) public {
        require(msg.sender == _controller, "ERR_NOT_CONTROLLER");
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

    function metadataLastUpdated() public view virtual returns (uint64) {
        return _metadataLastUpdated;
    }
}