pragma solidity ^0.5.0;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract BridgeToken is ERC20 {
    address private _controller; // has CONTROL role

    constructor() public {
        _controller = msg.sender;
    }

    function mint(address beneficiary, uint256 amount) public {
        require(msg.sender == _controller, "ERR_NOT_CONTROLLER");
        _mint(beneficiary, amount);
    }

    function burn(address act, uint256 amount) public {
        require(msg.sender == _controller, "ERR_NOT_CONTROLLER");
        _burn(act, amount);
    }
}
