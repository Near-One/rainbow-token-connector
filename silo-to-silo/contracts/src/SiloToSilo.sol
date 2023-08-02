// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs, PromiseResultStatus, PromiseWithCallback} from "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol";
import "@auroraisnear/aurora-sdk/aurora-sdk/Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./IEvmErc20.sol";

contract SiloToSilo is AccessControl {
    using AuroraSdk for NEAR;
    using AuroraSdk for PromiseCreateArgs;
    using AuroraSdk for PromiseWithCallback;

    bytes32 public constant CALLBACK_ROLE = keccak256("CALLBACK_ROLE");

    uint64 constant BASE_NEAR_GAS = 10_000_000_000_000;
    uint64 constant WITHDRAW_NEAR_GAS = 50_000_000_000_000;
    uint64 constant FT_TRANSFER_CALL_NEAR_GAS = 150_000_000_000_000;

    uint128 constant NEAR_STORAGE_DEPOSIT = 12_500_000_000_000_000_000_000;

    NEAR public near;
    string siloAccountId;

    //[auroraErc20Token] => tokenAccountIdOnNear
    mapping(IEvmErc20 => string) registeredTokens;

    //[auroraErc20Token][userAddressOnAurora] => userBalance
    mapping(IEvmErc20 => mapping(address => uint128)) balance;

    event TokenRegistered(IEvmErc20 token, string nearAccountId);

    constructor(address wnearAddress, string memory _siloAccountId) {
        near = AuroraSdk.initNear(IERC20_NEAR(wnearAddress));
        siloAccountId = _siloAccountId;

        _grantRole(CALLBACK_ROLE, AuroraSdk.nearRepresentitiveImplicitAddress(address(this)));
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // TODO: make it trustless
    function registerToken(IEvmErc20 token, string memory nearTokenAccountId) public onlyRole(DEFAULT_ADMIN_ROLE) {
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(NEAR_STORAGE_DEPOSIT));
        bytes memory args = bytes(
            string.concat('{"account_id": "', getNearAccountId(), '", "registration_only": true }')
        );

        PromiseCreateArgs memory callStorageDeposit = near.call(
            nearTokenAccountId,
            "storage_deposit",
            args,
            NEAR_STORAGE_DEPOSIT,
            BASE_NEAR_GAS
        );
        callStorageDeposit.transact();

        registeredTokens[token] = nearTokenAccountId;
        emit TokenRegistered(token, nearTokenAccountId);
    }

    function ftTransferCallToNear(
        IEvmErc20 token,
        uint128 amount,
        string calldata receiverId,
        string calldata message
    ) external {
        string storage tokenAccountId = registeredTokens[token];
        require(address(token) != address(0), "The token is not registered!");

        token.transferFrom(msg.sender, address(this), amount);
        // WARNING: The `withdrawToNear` method works asynchronously.
        // As a result, there is no guarantee that this method will be completed before `initTransfer`.
        // In case of such an error, the user will be able to call `withdraw` method and get his/her tokens back.
        // We expect such an error not to happen as long as transactions were executed in one shard.
        token.withdrawToNear(bytes(getNearAccountId()), amount);

        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "',
                receiverId,
                '", "amount": "',
                Strings.toString(amount),
                '", "msg": "',
                message,
                '"}'
            )
        );

        PromiseCreateArgs memory callFtTransfer = near.call(
            tokenAccountId,
            "ft_transfer_call",
            args,
            1,
            FT_TRANSFER_CALL_NEAR_GAS
        );
        
        bytes memory callbackArg = abi.encodeWithSelector(this.ftTransferCallCallback.selector, msg.sender, token, amount);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callFtTransfer.then(callback).transact();
    }

    function ftTransferCallCallback(address sender, IEvmErc20 token, uint128 amount) public onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);
        }

        balance[token][sender] += (amount - transferredAmount);
    }

    function withdraw(IEvmErc20 token) public {
        string storage tokenAccountId = registeredTokens[token];
        uint128 senderBalance = balance[token][msg.sender];

        require(senderBalance > 0, "The signer token balance = 0");

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));
        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "',
                siloAccountId,
                '", "amount": "',
                Strings.toString(senderBalance),
                '", "msg": "',
                _addressToString(msg.sender),
                '"}'
            )
        );
        PromiseCreateArgs memory callWithdraw = near.call(
            tokenAccountId,
            "ft_transfer_call",
            args,
            1,
            WITHDRAW_NEAR_GAS
        );
        bytes memory callbackArg = abi.encodeWithSelector(this.withdrawCallback.selector, msg.sender, token);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    function withdrawCallback(address sender, IEvmErc20 token) public onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `Withdraw` XCC is fail"
        );

        uint128 transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);

        if (transferredAmount > 0) {
            balance[token][sender] -= transferredAmount;
        }
    }

    function getNearAccountId() public view returns (string memory) {
        return string.concat(_addressToString(address(this)), ".", siloAccountId);
    }

    function getTokenAccountId(IEvmErc20 token) public view returns (string memory) {
        return registeredTokens[token];
    }

    function getUserBalance(IEvmErc20 token, address userAddress) public view returns (uint128) {
        return balance[token][userAddress];
    }

    function _addressToString(address auroraAddress) private pure returns (string memory) {
        return Utils.bytesToHex(abi.encodePacked(auroraAddress));
    }

    function _stringToUint(bytes memory b) private pure returns (uint128) {
        uint128 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            result = result * 10 + (uint128(uint8(b[i])) - 48);
        }
        return result;
    }
}
