pragma solidity ^0.8;
import "@openzeppelin/contracts/proxy/Proxy.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

contract BridgeTokenProxy is ERC1967Proxy, AccessControlUpgradeable {
    constructor(address _logic, bytes memory _data)
        ERC1967Proxy(_logic, _data)
    {
        __AccessControl_init();
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function upgradeTo(address implementation)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        super._upgradeTo(implementation);
    }
}
