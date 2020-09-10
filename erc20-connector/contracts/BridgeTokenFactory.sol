pragma solidity ^0.5.0;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";
import "rainbow-bridge-sol/nearprover/contracts/ProofDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/NearDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/Borsh.sol";

import "./BridgeToken.sol";
import "./ERC20Locker.sol";

contract BridgeTokenFactory is ERC20Locker {
    mapping(address => string) private _ethToNearToken;
    mapping(string => address) private _nearToEthToken;
    mapping(address => bool) private _isBridgeToken;

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

    struct LockResult {
        string token;
        uint128 amount;
        address recipient;
    }

    // BridgeTokenFactory is linked to the bridge token factory on NEAR side.
    // It also links to the prover that it uses to unlock the tokens.
    constructor(bytes memory nearTokenFactory, INearProver prover) public {
        nearTokenFactory_ = nearTokenFactory;
        prover_ = prover;
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

    function newBridgeToken(string calldata nearTokenId) external returns (BridgeToken) {
        require(!_isBridgeToken[_nearToEthToken[nearTokenId]], "ERR_BRIDGE_TOKEN_EXISTS");
        BridgeToken btoken = new BridgeToken();
        _isBridgeToken[address(btoken)] = true;
        _ethToNearToken[address(btoken)] = nearTokenId;
        _nearToEthToken[nearTokenId] = address(btoken);
        return btoken;
    }

    function deposit(bytes memory proofData, uint64 proofBlockHeight) public {
        ProofDecoder.ExecutionStatus memory status = _parseProof(proofData, proofBlockHeight);
        LockResult memory result = _decodeLockResult(status.successValue);
        require(_isBridgeToken[_nearToEthToken[result.token]], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken(_nearToEthToken[result.token]).mint(result.recipient, result.amount);
        emit Deposit(result.amount, result.recipient);
    }

    function withdraw(address token, uint256 amount, string memory recipient) public {
        require(_isBridgeToken[token], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken(token).burn(msg.sender, amount);
        emit Withdraw(_ethToNearToken[token], msg.sender, amount, recipient);
    }

    function _decodeLockResult(bytes memory data) internal pure returns(LockResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.token = string(borshData.decodeBytes());
        result.amount = borshData.decodeU128();
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
    }
}