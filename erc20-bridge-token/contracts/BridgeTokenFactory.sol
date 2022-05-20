pragma solidity ^0.8;

import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";
import "rainbow-bridge-sol/nearprover/contracts/ProofDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/Borsh.sol";

import "./Locker.sol";
import "./BridgeToken.sol";
import "./BridgeTokenProxy.sol";

contract BridgeTokenFactory is Locker, AccessControlUpgradeable, PausableUpgradeable{

    using Borsh for Borsh.Data;
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    mapping(address => string) private _ethToNearToken;
    mapping(string => address) private _nearToEthToken;
    mapping(address => bool) private _isBridgeToken;

    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    // Event when funds are withdrawn from Ethereum back to NEAR.
    event Withdraw (
        string token,
        address indexed sender,
        uint256 amount,
        string recipient
    );

    event Deposit (
        uint256 amount,
        address recipient
    );

    event SetMetadata (
        address token,
        string name,
        string symbol,
        uint8 decimals
    );

    struct LockResult {
        string token;
        uint128 amount;
        address recipient;
    }

    struct MetadataResult {
        string token;
        string name;
        string symbol;
        uint8 decimals;
        uint64 blockHeight;
    }


    // BridgeTokenFactory is linked to the bridge token factory on NEAR side.
    // It also links to the prover that it uses to unlock the tokens.
    function initialize(bytes memory _nearTokenFactory, INearProver _prover,  uint64 _minBlockAcceptanceHeight)
     public initializer{
        __AccessControl_init();
        __Pausable_init_unchained();
        __Locker_init(_nearTokenFactory, _prover, _minBlockAcceptanceHeight);
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender()); 
        _setupRole(PAUSE_ROLE, _msgSender()); 
    
    }

    function isBridgeToken(address token) external view returns (bool) {
        return _isBridgeToken[token];
    }

    function ethToNearToken(address token) external view returns (string memory) {
        require(_isBridgeToken[token], "ERR_NOT_BRIDGE_TOKEN");
        return _ethToNearToken[token];
    }

    function nearToEthToken(string calldata nearTokenId) external view returns (address) {
        require(_isBridgeToken[_nearToEthToken[nearTokenId]], "ERR_NOT_BRIDGE_TOKEN");
        return _nearToEthToken[nearTokenId];
    }

    function newBridgeToken(string calldata nearTokenId) external returns (BridgeTokenProxy) {
        require(!_isBridgeToken[_nearToEthToken[nearTokenId]], "ERR_BRIDGE_TOKEN_EXISTS");
        BridgeToken bridgeToken = new BridgeToken();
        BridgeTokenProxy bridgeTokenProxy = new BridgeTokenProxy(address(bridgeToken), abi.encodeWithSelector(BridgeToken(address(0)).initialize.selector, "", "", 0));
        _isBridgeToken[address(bridgeTokenProxy)] = true;
        _ethToNearToken[address(bridgeTokenProxy)] = nearTokenId;
        _nearToEthToken[nearTokenId] = address(bridgeTokenProxy);
        return bridgeTokenProxy;
    }

    function setMetadata(bytes memory proofData, uint64 proofBlockHeight) public whenNotPaused {
        ProofDecoder.ExecutionStatus memory status = _parseAndConsumeProof(proofData, proofBlockHeight);
        MetadataResult memory result = _decodeMetadataResult(status.successValue);
        require(_isBridgeToken[_nearToEthToken[result.token]], "ERR_NOT_BRIDGE_TOKEN");
        require(result.blockHeight >= BridgeToken(_nearToEthToken[result.token]).metadataLastUpdated(), "ERR_OLD_METADATA");
        BridgeToken(_nearToEthToken[result.token]).setMetadata(result.name, result.symbol, result.decimals, result.blockHeight);
        emit SetMetadata(_nearToEthToken[result.token], result.name, result.symbol, result.decimals);
    }

    function deposit(bytes memory proofData, uint64 proofBlockHeight) public whenNotPaused {
        ProofDecoder.ExecutionStatus memory status = _parseAndConsumeProof(proofData, proofBlockHeight);
        LockResult memory result = _decodeLockResult(status.successValue);
        require(_isBridgeToken[_nearToEthToken[result.token]], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken(_nearToEthToken[result.token]).mint(result.recipient, result.amount);
        emit Deposit(result.amount, result.recipient);
    }

    function withdraw(string memory token, address bridgeTokenProxy, uint256 amount, string memory recipient) public whenNotPaused {
        require(_isBridgeToken[_nearToEthToken[token]], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken(_nearToEthToken[token]).burn(msg.sender, amount);
        emit Withdraw(_ethToNearToken[bridgeTokenProxy], msg.sender, amount, recipient);
    }

    function _decodeMetadataResult(bytes memory data) internal pure returns(MetadataResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.token = string(borshData.decodeBytes());
        result.name = string(borshData.decodeBytes());
        result.symbol = string(borshData.decodeBytes());
        result.decimals = borshData.decodeU8();
        result.blockHeight = borshData.decodeU64();
        borshData.done();
    }

    function _decodeLockResult(bytes memory data) internal pure returns(LockResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.token = string(borshData.decodeBytes());
        result.amount = borshData.decodeU128();
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
        borshData.done();
    }
      function pause() external onlyRole(PAUSE_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSE_ROLE) {
        _unpause();
    }

    function upgradeToken(string calldata nearTokenId, address implementation) external  onlyRole(DEFAULT_ADMIN_ROLE) {
       require(_isBridgeToken[_nearToEthToken[nearTokenId]], "ERR_NOT_BRIDGE_TOKEN");
       BridgeTokenProxy proxy = BridgeTokenProxy(payable(_nearToEthToken[nearTokenId]));
       proxy.upgradeTo(implementation);
    }

}