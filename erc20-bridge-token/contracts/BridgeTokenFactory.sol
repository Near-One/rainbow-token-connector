// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";
import "rainbow-bridge-sol/nearprover/contracts/ProofDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/Borsh.sol";

import "./ProofConsumer.sol";
import "./BridgeToken.sol";
import "./ResultsDecoder.sol";
import "./SelectivePausableUpgradable.sol";

contract BridgeTokenFactory is
    ProofConsumer,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SelectivePausableUpgradable
{
    using Borsh for Borsh.Data;
    using SafeERC20 for IERC20;

    enum WhitelistMode {
        NotInitialized,
        Blocked,
        CheckToken,
        CheckAccountAndToken
    }

    mapping(address => string) private _ethToNearToken;
    mapping(string => address) private _nearToEthToken;
    mapping(address => bool) private _isBridgeToken;

    mapping(string => WhitelistMode) private _whitelistedTokens;
    mapping(bytes => bool) private _whitelistedAccounts;
    bool private _isWhitelistModeEnabled;

    address public tokenImplementationAddress;

    bytes32 public constant PAUSABLE_ADMIN_ROLE = keccak256("PAUSABLE_ADMIN_ROLE");
    uint constant UNPAUSED_ALL = 0;
    uint constant PAUSED_WITHDRAW = 1 << 0;
    uint constant PAUSED_DEPOSIT = 1 << 1;

    // Event when funds are withdrawn from Ethereum back to NEAR.
    event Withdraw(
        string token,
        address indexed sender,
        uint256 amount,
        string recipient,
        address indexed tokenEthAddress
    );

    event Deposit(string indexed token, uint256 amount, address recipient);

    event SetMetadata(
        address indexed token,
        string tokenId,
        string name,
        string symbol,
        uint8 decimals
    );

    // BridgeTokenFactory is linked to the bridge token factory on NEAR side.
    // It also links to the prover that it uses to unlock the tokens.
    function initialize(
        address _tokenImplementationAddress,
        bytes memory _nearTokenLocker,
        INearProver _prover,
        uint64 _minBlockAcceptanceHeight
    ) external initializer {
        require(_nearTokenLocker.length > 0, "Invalid Near Token Locker address");
        require(address(_prover) != address(0), "Invalid Near prover address");

        nearTokenLocker = _nearTokenLocker;
        prover = _prover;
        minBlockAcceptanceHeight = _minBlockAcceptanceHeight;
        tokenImplementationAddress = _tokenImplementationAddress;

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init_unchained();
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(PAUSABLE_ADMIN_ROLE, _msgSender());
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

    function newBridgeToken(
        bytes memory proofData,
        uint64 proofBlockHeight
    ) external returns (address) {
        ProofDecoder.ExecutionStatus memory status = _parseAndConsumeProof(
            proofData,
            proofBlockHeight
        );
        ResultsDecoder.MetadataResult memory result = ResultsDecoder.decodeMetadataResult(
            status.successValue
        );

        require(!_isBridgeToken[_nearToEthToken[result.token]], "ERR_TOKEN_EXIST");

        address bridgeTokenProxy = address(
            new ERC1967Proxy(
                tokenImplementationAddress,
                abi.encodeWithSelector(
                    BridgeToken.initialize.selector,
                    result.name,
                    result.symbol,
                    result.decimals
                )
            )
        );

        emit SetMetadata(
            bridgeTokenProxy,
            result.token,
            result.name,
            result.symbol,
            result.decimals
        );

        _isBridgeToken[address(bridgeTokenProxy)] = true;
        _ethToNearToken[address(bridgeTokenProxy)] = result.token;
        _nearToEthToken[result.token] = address(bridgeTokenProxy);

        return bridgeTokenProxy;
    }

    function setMetadata(
        string calldata token,
        string calldata name,
        string calldata symbol
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_isBridgeToken[_nearToEthToken[token]], "ERR_NOT_BRIDGE_TOKEN");

        BridgeToken bridgeToken = BridgeToken(_nearToEthToken[token]);

        bridgeToken.setMetadata(name, symbol, bridgeToken.decimals());

        emit SetMetadata(
            address(bridgeToken),
            token,
            name,
            symbol,
            bridgeToken.decimals()
        );
    }

    function deposit(
        bytes memory proofData,
        uint64 proofBlockHeight
    ) external whenNotPaused(PAUSED_DEPOSIT) {
        ProofDecoder.ExecutionStatus memory status = _parseAndConsumeProof(
            proofData,
            proofBlockHeight
        );
        ResultsDecoder.LockResult memory result = ResultsDecoder.decodeLockResult(
            status.successValue
        );

        require(_isBridgeToken[_nearToEthToken[result.token]], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken(_nearToEthToken[result.token]).mint(result.recipient, result.amount);

        emit Deposit(result.token, result.amount, result.recipient);
    }

    function withdraw(
        string memory token,
        uint256 amount,
        string memory recipient
    ) external whenNotPaused(PAUSED_WITHDRAW) {
        _checkWhitelistedToken(token, msg.sender);
        require(_isBridgeToken[_nearToEthToken[token]], "ERR_NOT_BRIDGE_TOKEN");

        address tokenEthAddress = _nearToEthToken[token];
        BridgeToken(tokenEthAddress).burn(msg.sender, amount);

        emit Withdraw(token, msg.sender, amount, recipient, tokenEthAddress);
    }

    function pause(uint flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseDeposit() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause(pausedFlags() | PAUSED_DEPOSIT);
    }

    function pauseWithdraw() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause(pausedFlags() | PAUSED_WITHDRAW);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint flags = PAUSED_DEPOSIT | PAUSED_WITHDRAW;
        _pause(flags);
    }

    function isWhitelistModeEnabled() external view returns (bool) {
        return _isWhitelistModeEnabled;
    }

    function getTokenWhitelistMode(
        string calldata token
    ) external view returns (WhitelistMode) {
        return _whitelistedTokens[token];
    }

    function isAccountWhitelistedForToken(
        string calldata token,
        address account
    ) external view returns (bool) {
        return _whitelistedAccounts[abi.encodePacked(token, account)];
    }

    function upgradeToken(
        string calldata nearTokenId,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_isBridgeToken[_nearToEthToken[nearTokenId]], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(payable(_nearToEthToken[nearTokenId]));
        proxy.upgradeToAndCall(implementation, bytes(""));
    }

    function enableWhitelistMode() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _isWhitelistModeEnabled = true;
    }

    function disableWhitelistMode() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _isWhitelistModeEnabled = false;
    }

    function setTokenWhitelistMode(
        string calldata token,
        WhitelistMode mode
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _whitelistedTokens[token] = mode;
    }

    function addAccountToWhitelist(
        string calldata token,
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            _whitelistedTokens[token] != WhitelistMode.NotInitialized,
            "ERR_NOT_INITIALIZED_WHITELIST_TOKEN"
        );
        _whitelistedAccounts[abi.encodePacked(token, account)] = true;
    }

    function removeAccountFromWhitelist(
        string calldata token,
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delete _whitelistedAccounts[abi.encodePacked(token, account)];
    }

    function _checkWhitelistedToken(string memory token, address account) internal view {
        if (!_isWhitelistModeEnabled) {
            return;
        }

        WhitelistMode tokenMode = _whitelistedTokens[token];
        require(
            tokenMode != WhitelistMode.NotInitialized,
            "ERR_NOT_INITIALIZED_WHITELIST_TOKEN"
        );
        require(tokenMode != WhitelistMode.Blocked, "ERR_WHITELIST_TOKEN_BLOCKED");

        if (tokenMode == WhitelistMode.CheckAccountAndToken) {
            require(
                _whitelistedAccounts[abi.encodePacked(token, account)],
                "ERR_ACCOUNT_NOT_IN_WHITELIST"
            );
        }
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
