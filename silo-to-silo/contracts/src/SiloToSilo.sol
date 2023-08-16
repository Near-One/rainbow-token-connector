// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs, PromiseResultStatus, PromiseWithCallback} from "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol";
import "@auroraisnear/aurora-sdk/aurora-sdk/Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./IEvmErc20.sol";

struct TokenInfo {
    string nearTokenAccountId;
    bool isStorageRegistered;
}

contract SiloToSilo is AccessControl {
    using AuroraSdk for NEAR;
    using AuroraSdk for PromiseCreateArgs;
    using AuroraSdk for PromiseWithCallback;

    bytes32 public constant CALLBACK_ROLE = keccak256("CALLBACK_ROLE");

    uint64 constant BASE_NEAR_GAS = 10_000_000_000_000;
    uint64 constant WITHDRAW_NEAR_GAS = 50_000_000_000_000;
    uint64 constant FT_TRANSFER_CALL_NEAR_GAS = 150_000_000_000_000;
    uint128 constant ASCII_0 = 48;
    uint128 constant ASCII_9 = 57;
    uint128 constant ONE_YOCTO = 1;
    uint128 constant NO_DEPOSIT = 0;

    NEAR public near;
    string public siloAccountId;

    //[auroraErc20Token] => tokenAccountIdOnNear
    mapping(IEvmErc20 => TokenInfo) registeredTokens;

    //[auroraErc20Token][userAddressOnAurora] => userBalance
    mapping(IEvmErc20 => mapping(address => uint256)) balance;

    event TokenRegistered(IEvmErc20 token, string nearAccountId);

    constructor(address wnearAddress, string memory _siloAccountId) {
        near = AuroraSdk.initNear(IERC20_NEAR(wnearAddress));
        siloAccountId = _siloAccountId;

        _grantRole(CALLBACK_ROLE, AuroraSdk.nearRepresentitiveImplicitAddress(address(this)));
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function registerToken(IEvmErc20 token) external {
        PromiseCreateArgs memory callGetNep141FromErc20 = near.call(
            siloAccountId,
            "get_nep141_from_erc20",
            abi.encodePacked(address(token)),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );

        PromiseCreateArgs memory callback = near.auroraCall(
            address(this),
            abi.encodeWithSelector(this.getNep141FromErc20Callback.selector, token),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );

        callGetNep141FromErc20.then(callback).transact();
    }

    function getNep141FromErc20Callback(IEvmErc20 token) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `get_nep141_from_erc20` XCC is fail"
        );

        string memory nearTokenAccountId = string(AuroraSdk.promiseResult(0).output);
        registeredTokens[token] = TokenInfo(nearTokenAccountId, false);
        emit TokenRegistered(token, nearTokenAccountId);
    }

    function storageDeposit(IEvmErc20 token, uint128 storageDepositAmount) external {
        string storage tokenAccountId = registeredTokens[token].nearTokenAccountId;
        require(bytes(tokenAccountId).length > 0, "The token is not registered!");

        PromiseCreateArgs memory callStorageDeposit = near.call(
            tokenAccountId,
            "storage_deposit",
            bytes(string.concat('{"account_id": "', getNearAccountId(), '", "registration_only": true }')),
            storageDepositAmount,
            BASE_NEAR_GAS
        );

        PromiseCreateArgs memory callback = near.auroraCall(
            address(this),
            abi.encodeWithSelector(this.storageDepositCallback.selector, token),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );
        callStorageDeposit.then(callback).transact();
    }

    function storageDepositCallback(IEvmErc20 token) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `storage_deposit` XCC is fail"
        );
        registeredTokens[token].isStorageRegistered = true;
    }

    function ftTransferCallToNear(
        IEvmErc20 token,
        uint256 amount,
        string calldata receiverId,
        string calldata message
    ) external {
        require(near.wNEAR.balanceOf(address(this)) >= ONE_YOCTO, "Not enough wNEAR balance");

        TokenInfo storage tokenInfo = registeredTokens[token];
        require(tokenInfo.isStorageRegistered, "The token storage is not registered!");

        token.transferFrom(msg.sender, address(this), amount);
        // WARNING: The `withdrawToNear` method works asynchronously.
        // As a result, there is no guarantee that this method will be completed before `initTransfer`.
        // In case of such an error, the user will be able to call `withdraw` method and get his/her tokens back.
        // We expect such an error not to happen as long as transactions were executed in one shard.
        token.withdrawToNear(bytes(getNearAccountId()), amount);

        PromiseCreateArgs memory callFtTransfer = _callWithoutTransferWNear(
            near,
            tokenInfo.nearTokenAccountId,
            "ft_transfer_call",
            bytes(
                string.concat(
                    '{"receiver_id": "',
                    receiverId,
                    '", "amount": "',
                    Strings.toString(amount),
                    '", "msg": "',
                    message,
                    '"}'
                )
            ),
            ONE_YOCTO,
            FT_TRANSFER_CALL_NEAR_GAS
        );

        PromiseCreateArgs memory callback = near.auroraCall(
            address(this),
            abi.encodeWithSelector(this.ftTransferCallCallback.selector, msg.sender, token, amount),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );

        callFtTransfer.then(callback).transact();
    }

    function ftTransferCallCallback(address sender, IEvmErc20 token, uint256 amount) external onlyRole(CALLBACK_ROLE) {
        uint256 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);
        }

        balance[token][sender] += (amount - transferredAmount);
    }

    function withdraw(IEvmErc20 token) external {
        require(near.wNEAR.balanceOf(address(this)) >= ONE_YOCTO, "Not enough wNEAR balance");

        string storage tokenAccountId = registeredTokens[token].nearTokenAccountId;
        require(bytes(tokenAccountId).length > 0, "The token is not registered!");

        uint256 senderBalance = balance[token][msg.sender];
        require(senderBalance > 0, "The signer token balance = 0");

        PromiseCreateArgs memory callWithdraw = _callWithoutTransferWNear(
            near,
            tokenAccountId,
            "ft_transfer_call",
            bytes(
                string.concat(
                    '{"receiver_id": "',
                    siloAccountId,
                    '", "amount": "',
                    Strings.toString(senderBalance),
                    '", "msg": "',
                    _addressToString(msg.sender),
                    '"}'
                )
            ),
            ONE_YOCTO,
            WITHDRAW_NEAR_GAS
        );

        PromiseCreateArgs memory callback = near.auroraCall(
            address(this),
            abi.encodeWithSelector(this.withdrawCallback.selector, msg.sender, token),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );

        callWithdraw.then(callback).transact();
    }

    function withdrawCallback(address sender, IEvmErc20 token) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `Withdraw` XCC is fail"
        );

        uint256 transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);
        balance[token][sender] -= transferredAmount;
    }

    function getNearAccountId() public view returns (string memory) {
        return string.concat(_addressToString(address(this)), ".", siloAccountId);
    }

    function getTokenAccountId(IEvmErc20 token) public view returns (string memory) {
        return registeredTokens[token].nearTokenAccountId;
    }

    function isStorageRegistered(IEvmErc20 token) public view returns (bool) {
        return registeredTokens[token].isStorageRegistered;
    }

    function getUserBalance(IEvmErc20 token, address userAddress) public view returns (uint256) {
        return balance[token][userAddress];
    }

    function _addressToString(address auroraAddress) private pure returns (string memory) {
        return Utils.bytesToHex(abi.encodePacked(auroraAddress));
    }

    function _stringToUint(bytes memory b) private pure returns (uint256) {
        uint256 result = 0;

        for (uint256 i = 0; i < b.length; i++) {
            uint256 v = uint256(uint8(b[i]));
            if (v >= ASCII_0 && v <= ASCII_9) {
                result = result * 10 + (v - ASCII_0);
            }
        }

        return result;
    }

    /// Creates a base promise. This is not immediately scheduled for execution
    /// until transact is called. It can be combined with other promises using
    /// `then` combinator.
    ///
    /// Input is not checekd during promise creation. If it is invalid, the
    /// transaction will be scheduled either way, but it will fail during execution.
    function _callWithoutTransferWNear(
        NEAR storage _near,
        string memory targetAccountId,
        string memory method,
        bytes memory args,
        uint128 nearBalance,
        uint64 nearGas
    ) private view returns (PromiseCreateArgs memory) {
        require(_near.initialized, "Near isn't initialized");
        return PromiseCreateArgs(targetAccountId, method, args, nearBalance, nearGas);
    }
}
