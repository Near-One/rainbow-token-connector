
// File: @openzeppelin/contracts/token/ERC20/IERC20.sol

pragma solidity ^0.5.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP. Does not include
 * the optional functions; to access them see {ERC20Detailed}.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// File: @openzeppelin/contracts/math/SafeMath.sol

pragma solidity ^0.5.0;

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     *
     * _Available since v2.4.0._
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     *
     * _Available since v2.4.0._
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     *
     * _Available since v2.4.0._
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

// File: @openzeppelin/contracts/utils/Address.sol

pragma solidity ^0.5.5;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following 
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != accountHash && codehash != 0x0);
    }

    /**
     * @dev Converts an `address` into `address payable`. Note that this is
     * simply a type cast: the actual underlying value is not changed.
     *
     * _Available since v2.4.0._
     */
    function toPayable(address account) internal pure returns (address payable) {
        return address(uint160(account));
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     *
     * _Available since v2.4.0._
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-call-value
        (bool success, ) = recipient.call.value(amount)("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
}

// File: @openzeppelin/contracts/token/ERC20/SafeERC20.sol

pragma solidity ^0.5.0;




/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for ERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

// File: rainbow-bridge-sol/nearprover/contracts/INearProver.sol

pragma solidity ^0.5.0;

interface INearProver {
    function proveOutcome(bytes calldata proofData, uint64 blockHeight) external view returns(bool);
}

// File: rainbow-bridge-sol/nearbridge/contracts/Borsh.sol

pragma solidity ^0.5.0;



library Borsh {

    using SafeMath for uint256;

    struct Data {
        uint256 offset;
        bytes raw;
    }

    function from(bytes memory data) internal pure returns(Data memory) {
        return Data({
            offset: 0,
            raw: data
        });
    }

    modifier shift(Data memory data, uint256 size) {
        // require(data.raw.length > data.offset + size, "Borsh: Out of range");
        _;
        data.offset += size;
    }

    function finished(Data memory data) internal pure returns(bool) {
        return data.offset == data.raw.length;
    }

    function peekKeccak256(Data memory data, uint256 length) internal pure returns(bytes32 res) {
        return bytesKeccak256(data.raw, data.offset, length);
    }

    function bytesKeccak256(bytes memory ptr, uint256 offset, uint256 length) internal pure returns(bytes32 res) {
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            res := keccak256(add(add(ptr, 32), offset), length)
        }
    }

    function peekSha256(Data memory data, uint256 length) internal view returns(bytes32) {
        return bytesSha256(data.raw, data.offset, length);
    }

    function bytesSha256(bytes memory ptr, uint256 offset, uint256 length) internal view returns(bytes32) {
        bytes32[1] memory result;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            pop(staticcall(gas, 0x02, add(add(ptr, 32), offset), length, result, 32))
        }
        return result[0];
    }

    function decodeU8(Data memory data) internal pure shift(data, 1) returns(uint8 value) {
        value = uint8(data.raw[data.offset]);
    }

    function decodeI8(Data memory data) internal pure shift(data, 1) returns(int8 value) {
        value = int8(data.raw[data.offset]);
    }

    function decodeU16(Data memory data) internal pure returns(uint16 value) {
        value = uint16(decodeU8(data));
        value |= (uint16(decodeU8(data)) << 8);
    }

    function decodeI16(Data memory data) internal pure returns(int16 value) {
        value = int16(decodeI8(data));
        value |= (int16(decodeI8(data)) << 8);
    }

    function decodeU32(Data memory data) internal pure returns(uint32 value) {
        value = uint32(decodeU16(data));
        value |= (uint32(decodeU16(data)) << 16);
    }

    function decodeI32(Data memory data) internal pure returns(int32 value) {
        value = int32(decodeI16(data));
        value |= (int32(decodeI16(data)) << 16);
    }

    function decodeU64(Data memory data) internal pure returns(uint64 value) {
        value = uint64(decodeU32(data));
        value |= (uint64(decodeU32(data)) << 32);
    }

    function decodeI64(Data memory data) internal pure returns(int64 value) {
        value = int64(decodeI32(data));
        value |= (int64(decodeI32(data)) << 32);
    }

    function decodeU128(Data memory data) internal pure returns(uint128 value) {
        value = uint128(decodeU64(data));
        value |= (uint128(decodeU64(data)) << 64);
    }

    function decodeI128(Data memory data) internal pure returns(int128 value) {
        value = int128(decodeI64(data));
        value |= (int128(decodeI64(data)) << 64);
    }

    function decodeU256(Data memory data) internal pure returns(uint256 value) {
        value = uint256(decodeU128(data));
        value |= (uint256(decodeU128(data)) << 128);
    }

    function decodeI256(Data memory data) internal pure returns(int256 value) {
        value = int256(decodeI128(data));
        value |= (int256(decodeI128(data)) << 128);
    }

    function decodeBool(Data memory data) internal pure returns(bool value) {
        value = (decodeU8(data) != 0);
    }

    function decodeBytes(Data memory data) internal pure returns(bytes memory value) {
        value = new bytes(decodeU32(data));
        for (uint i = 0; i < value.length; i++) {
            value[i] = byte(decodeU8(data));
        }
    }

    function decodeBytes32(Data memory data) internal pure shift(data, 32) returns(bytes32 value) {
        bytes memory raw = data.raw;
        uint256 offset = data.offset;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            value := mload(add(add(raw, 32), offset))
        }
    }

    function decodeBytes20(Data memory data) internal pure returns(bytes20 value) {
        for (uint i = 0; i < 20; i++) {
            value |= bytes20(byte(decodeU8(data)) & 0xFF) >> (i * 8);
        }
    }

    // Public key

    struct SECP256K1PublicKey {
        uint256 x;
        uint256 y;
    }

    function decodeSECP256K1PublicKey(Borsh.Data memory data) internal pure returns(SECP256K1PublicKey memory key) {
        key.x = decodeU256(data);
        key.y = decodeU256(data);
    }

    struct ED25519PublicKey {
        bytes32 xy;
    }

    function decodeED25519PublicKey(Borsh.Data memory data) internal pure returns(ED25519PublicKey memory key) {
        key.xy = decodeBytes32(data);
    }

    // Signature

    struct SECP256K1Signature {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    function decodeSECP256K1Signature(Borsh.Data memory data) internal pure returns(SECP256K1Signature memory sig) {
        sig.r = decodeBytes32(data);
        sig.s = decodeBytes32(data);
        sig.v = decodeU8(data);
    }

    struct ED25519Signature {
        bytes32[2] rs;
    }

    function decodeED25519Signature(Borsh.Data memory data) internal pure returns(ED25519Signature memory sig) {
        sig.rs[0] = decodeBytes32(data);
        sig.rs[1] = decodeBytes32(data);
    }
}

// File: rainbow-bridge-sol/nearbridge/contracts/NearDecoder.sol

pragma solidity ^0.5.0;




library NearDecoder {

    using Borsh for Borsh.Data;
    using NearDecoder for Borsh.Data;

    struct PublicKey {
        uint8 enumIndex;

        Borsh.ED25519PublicKey ed25519;
        Borsh.SECP256K1PublicKey secp256k1;
    }

    function decodePublicKey(Borsh.Data memory data) internal pure returns(PublicKey memory key) {
        key.enumIndex = data.decodeU8();

        if (key.enumIndex == 0) {
            key.ed25519 = data.decodeED25519PublicKey();
        }
        else if (key.enumIndex == 1) {
            key.secp256k1 = data.decodeSECP256K1PublicKey();
        }
        else {
            revert("NearBridge: Only ED25519 and SECP256K1 public keys are supported");
        }
    }

    struct ValidatorStake {
        string account_id;
        PublicKey public_key;
        uint128 stake;
    }

    function decodeValidatorStake(Borsh.Data memory data) internal pure returns(ValidatorStake memory validatorStake) {
        validatorStake.account_id = string(data.decodeBytes());
        validatorStake.public_key = data.decodePublicKey();
        validatorStake.stake = data.decodeU128();
    }

    struct OptionalValidatorStakes {
        bool none;

        ValidatorStake[] validatorStakes;
        bytes32 hash; // Additional computable element
    }

    function decodeOptionalValidatorStakes(Borsh.Data memory data) internal view returns(OptionalValidatorStakes memory stakes) {
        stakes.none = (data.decodeU8() == 0);
        if (!stakes.none) {
            uint256 start = data.offset;

            stakes.validatorStakes = new ValidatorStake[](data.decodeU32());
            for (uint i = 0; i < stakes.validatorStakes.length; i++) {
                stakes.validatorStakes[i] = data.decodeValidatorStake();
            }

            uint256 stop = data.offset;
            data.offset = start;
            stakes.hash = data.peekSha256(stop - start);
            data.offset = stop;
        }
    }

    struct Signature {
        uint8 enumIndex;

        Borsh.ED25519Signature ed25519;
        Borsh.SECP256K1Signature secp256k1;
    }

    function decodeSignature(Borsh.Data memory data) internal pure returns(Signature memory sig) {
        sig.enumIndex = data.decodeU8();

        if (sig.enumIndex == 0) {
            sig.ed25519 = data.decodeED25519Signature();
        }
        else if (sig.enumIndex == 1) {
            sig.secp256k1 = data.decodeSECP256K1Signature();
        }
        else {
            revert("NearBridge: Only ED25519 and SECP256K1 signatures are supported");
        }
    }

    struct OptionalSignature {
        bool none;
        Signature signature;
    }

    function decodeOptionalSignature(Borsh.Data memory data) internal pure returns(OptionalSignature memory sig) {
        sig.none = (data.decodeU8() == 0);
        if (!sig.none) {
            sig.signature = data.decodeSignature();
        }
    }

    struct LightClientBlock {
        bytes32 prev_block_hash;
        bytes32 next_block_inner_hash;
        BlockHeaderInnerLite inner_lite;
        bytes32 inner_rest_hash;
        OptionalValidatorStakes next_bps;
        OptionalSignature[] approvals_after_next;

        bytes32 hash;
        bytes32 next_hash;
    }

    struct InitialValidators {
        ValidatorStake[] validator_stakes;
    }

    function decodeInitialValidators(Borsh.Data memory data) internal view returns(InitialValidators memory validators) {
        validators.validator_stakes = new ValidatorStake[](data.decodeU32());
        for (uint i = 0; i < validators.validator_stakes.length; i++) {
            validators.validator_stakes[i] = data.decodeValidatorStake();
        }
    }

    function decodeLightClientBlock(Borsh.Data memory data) internal view returns(LightClientBlock memory header) {
        header.prev_block_hash = data.decodeBytes32();
        header.next_block_inner_hash = data.decodeBytes32();
        header.inner_lite = data.decodeBlockHeaderInnerLite();
        header.inner_rest_hash = data.decodeBytes32();
        header.next_bps = data.decodeOptionalValidatorStakes();

        header.approvals_after_next = new OptionalSignature[](data.decodeU32());
        for (uint  i = 0; i < header.approvals_after_next.length; i++) {
            header.approvals_after_next[i] = data.decodeOptionalSignature();
        }

        header.hash = sha256(abi.encodePacked(
            sha256(abi.encodePacked(
                header.inner_lite.hash,
                header.inner_rest_hash
            )),
            header.prev_block_hash
        ));

        header.next_hash = sha256(abi.encodePacked(
            header.next_block_inner_hash,
            header.hash
        ));
    }

    struct BlockHeaderInnerLite {
        uint64 height;              /// Height of this block since the genesis block (height 0).
        bytes32 epoch_id;           /// Epoch start hash of this block's epoch. Used for retrieving validator information
        bytes32 next_epoch_id;
        bytes32 prev_state_root;    /// Root hash of the state at the previous block.
        bytes32 outcome_root;       /// Root of the outcomes of transactions and receipts.
        uint64 timestamp;           /// Timestamp at which the block was built.
        bytes32 next_bp_hash;       /// Hash of the next epoch block producers set
        bytes32 block_merkle_root;

        bytes32 hash; // Additional computable element
    }

    function decodeBlockHeaderInnerLite(Borsh.Data memory data) internal view returns(BlockHeaderInnerLite memory header) {
        header.hash = data.peekSha256(208);
        header.height = data.decodeU64();
        header.epoch_id = data.decodeBytes32();
        header.next_epoch_id = data.decodeBytes32();
        header.prev_state_root = data.decodeBytes32();
        header.outcome_root = data.decodeBytes32();
        header.timestamp = data.decodeU64();
        header.next_bp_hash = data.decodeBytes32();
        header.block_merkle_root = data.decodeBytes32();
    }
}

// File: rainbow-bridge-sol/nearprover/contracts/ProofDecoder.sol

pragma solidity ^0.5.0;




library ProofDecoder {
    using Borsh for Borsh.Data;
    using ProofDecoder for Borsh.Data;
    using NearDecoder for Borsh.Data;

    struct FullOutcomeProof {
        ExecutionOutcomeWithIdAndProof outcome_proof;
        MerklePath outcome_root_proof; // TODO: now empty array
        BlockHeaderLight block_header_lite;
        MerklePath block_proof;
    }

    function decodeFullOutcomeProof(Borsh.Data memory data) internal view returns(FullOutcomeProof memory proof) {
        proof.outcome_proof = data.decodeExecutionOutcomeWithIdAndProof();
        proof.outcome_root_proof = data.decodeMerklePath();
        proof.block_header_lite = data.decodeBlockHeaderLight();
        proof.block_proof = data.decodeMerklePath();
    }

    struct BlockHeaderLight {
        bytes32 prev_block_hash;
        bytes32 inner_rest_hash;
        NearDecoder.BlockHeaderInnerLite inner_lite;

        bytes32 hash; // Computable
    }

    function decodeBlockHeaderLight(Borsh.Data memory data) internal view returns(BlockHeaderLight memory header) {
        header.prev_block_hash = data.decodeBytes32();
        header.inner_rest_hash = data.decodeBytes32();
        header.inner_lite = data.decodeBlockHeaderInnerLite();

        header.hash = sha256(abi.encodePacked(
            sha256(abi.encodePacked(
                header.inner_lite.hash,
                header.inner_rest_hash
            )),
            header.prev_block_hash
        ));
    }

    struct ExecutionStatus {
        uint8 enumIndex;
        bool unknown;
        bool failed;
        bytes successValue;         /// The final action succeeded and returned some value or an empty vec.
        bytes32 successReceiptId;   /// The final action of the receipt returned a promise or the signed
                                    /// transaction was converted to a receipt. Contains the receipt_id of the generated receipt.
    }

    function decodeExecutionStatus(Borsh.Data memory data) internal pure returns(ExecutionStatus memory executionStatus) {
        executionStatus.enumIndex = data.decodeU8();
        if (executionStatus.enumIndex == 0) {
            executionStatus.unknown = true;
        } else
        if (executionStatus.enumIndex == 1) {
            //revert("NearDecoder: decodeExecutionStatus failure case not implemented yet");
            // Can avoid revert since ExecutionStatus is latest field in all parent structures
            executionStatus.failed = true;
        } else
        if (executionStatus.enumIndex == 2) {
            executionStatus.successValue = data.decodeBytes();
        } else
        if (executionStatus.enumIndex == 3) {
            executionStatus.successReceiptId = data.decodeBytes32();
        } else {
            revert("NearDecoder: decodeExecutionStatus index out of range");
        }
    }

    struct ExecutionOutcome {
        bytes[] logs;           /// Logs from this transaction or receipt.
        bytes32[] receipt_ids;  /// Receipt IDs generated by this transaction or receipt.
        uint64 gas_burnt;       /// The amount of the gas burnt by the given transaction or receipt.
        uint128 tokens_burnt;   /// The total number of the tokens burnt by the given transaction or receipt.
        bytes executor_id;  /// Hash of the transaction or receipt id that produced this outcome.
        ExecutionStatus status; /// Execution status. Contains the result in case of successful execution.

        bytes32[] merkelization_hashes;
    }

    function decodeExecutionOutcome(Borsh.Data memory data) internal view returns(ExecutionOutcome memory outcome) {
        outcome.logs = new bytes[](data.decodeU32());
        for (uint i = 0; i < outcome.logs.length; i++) {
            outcome.logs[i] = data.decodeBytes();
        }

        uint256 start = data.offset;
        outcome.receipt_ids = new bytes32[](data.decodeU32());
        for (uint i = 0; i < outcome.receipt_ids.length; i++) {
            outcome.receipt_ids[i] = data.decodeBytes32();
        }
        outcome.gas_burnt = data.decodeU64();
        outcome.tokens_burnt = data.decodeU128();
        outcome.executor_id = data.decodeBytes();
        outcome.status = data.decodeExecutionStatus();
        uint256 stop = data.offset;

        outcome.merkelization_hashes = new bytes32[](1 + outcome.logs.length);
        data.offset = start;
        outcome.merkelization_hashes[0] = data.peekSha256(stop - start);
        data.offset = stop;
        for (uint i = 0; i < outcome.logs.length; i++) {
            outcome.merkelization_hashes[i + 1] = sha256(outcome.logs[i]);
        }
    }

    struct ExecutionOutcomeWithId {
        bytes32 id; /// The transaction hash or the receipt ID.
        ExecutionOutcome outcome;

        bytes32 hash;
    }

    function decodeExecutionOutcomeWithId(Borsh.Data memory data) internal view returns(ExecutionOutcomeWithId memory outcome) {
        outcome.id = data.decodeBytes32();
        outcome.outcome = data.decodeExecutionOutcome();

        uint256 len = 1 + outcome.outcome.merkelization_hashes.length;
        outcome.hash = sha256(
            abi.encodePacked(
                uint8((len >> 0) & 0xFF),
                uint8((len >> 8) & 0xFF),
                uint8((len >> 16) & 0xFF),
                uint8((len >> 24) & 0xFF),
                outcome.id,
                outcome.outcome.merkelization_hashes
            )
        );
    }

    struct MerklePathItem {
        bytes32 hash;
        uint8 direction; // 0 = left, 1 = right
    }

    function decodeMerklePathItem(Borsh.Data memory data) internal pure returns(MerklePathItem memory item) {
        item.hash = data.decodeBytes32();
        item.direction = data.decodeU8();
        require(item.direction < 2, "ProofDecoder: MerklePathItem direction should be 0 or 1");
    }

    struct MerklePath {
        MerklePathItem[] items;
    }

    function decodeMerklePath(Borsh.Data memory data) internal pure returns(MerklePath memory path) {
        path.items = new MerklePathItem[](data.decodeU32());
        for (uint i = 0; i < path.items.length; i++) {
            path.items[i] = data.decodeMerklePathItem();
        }
    }

    struct ExecutionOutcomeWithIdAndProof {
        MerklePath proof;
        bytes32 block_hash;
        ExecutionOutcomeWithId outcome_with_id;
    }

    function decodeExecutionOutcomeWithIdAndProof(Borsh.Data memory data)
        internal
        view
        returns(ExecutionOutcomeWithIdAndProof memory outcome)
    {
        outcome.proof = data.decodeMerklePath();
        outcome.block_hash = data.decodeBytes32();
        outcome.outcome_with_id = data.decodeExecutionOutcomeWithId();
    }
}

// File: contracts/Locker.sol

pragma solidity ^0.5.0;





contract Locker {
    using Borsh for Borsh.Data;
    using ProofDecoder for Borsh.Data;
    using NearDecoder for Borsh.Data;

    INearProver public prover_;
    bytes public nearTokenFactory_;

    // OutcomeReciptId -> Used
    mapping(bytes32 => bool) public usedEvents_;

    function _parseProof(bytes memory proofData, uint64 proofBlockHeight) internal returns(ProofDecoder.ExecutionStatus memory result) {
        require(prover_.proveOutcome(proofData, proofBlockHeight), "Proof should be valid");

        // Unpack the proof and extract the execution outcome.
        Borsh.Data memory borshData = Borsh.from(proofData);
        ProofDecoder.FullOutcomeProof memory fullOutcomeProof = borshData.decodeFullOutcomeProof();
        require(borshData.finished(), "Argument should be exact borsh serialization");

        bytes32 receiptId = fullOutcomeProof.outcome_proof.outcome_with_id.outcome.receipt_ids[0];
        require(!usedEvents_[receiptId], "The burn event cannot be reused");
        usedEvents_[receiptId] = true;

        require(keccak256(fullOutcomeProof.outcome_proof.outcome_with_id.outcome.executor_id) == keccak256(nearTokenFactory_),
        "Can only unlock tokens from the linked mintable fungible token on Near blockchain.");

        result = fullOutcomeProof.outcome_proof.outcome_with_id.outcome.status;
        require(!result.failed, "Cannot use failed execution outcome for unlocking the tokens.");
        require(!result.unknown, "Cannot use unknown execution outcome for unlocking the tokens.");
    }
}

// File: contracts/ERC20Locker.sol

pragma solidity ^0.5.0;








contract ERC20Locker is Locker {
    using SafeERC20 for IERC20;

    event Locked (
        address indexed token,
        address indexed sender,
        uint256 amount,
        string accountId
    );

    event Unlocked (
        uint128 amount,
        address recipient
    );

    // Function output from burning fungible token on Near side.
    struct BurnResult {
        uint128 amount;
        address token;
        address recipient;
    }

    function lockToken(address ethToken, uint256 amount, string memory accountId) public {
        IERC20(ethToken).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(address(ethToken), msg.sender, amount, accountId);
    }

    function burnResult(bytes memory proofData, uint64 proofBlockHeight) public returns(address) {
        ProofDecoder.ExecutionStatus memory status = _parseProof(proofData, proofBlockHeight);
        BurnResult memory result = _decodeBurnResult(status.successValue);
        return result.token;
    }

    function unlockToken(bytes memory proofData, uint64 proofBlockHeight) public {
        ProofDecoder.ExecutionStatus memory status = _parseProof(proofData, proofBlockHeight);
        BurnResult memory result = _decodeBurnResult(status.successValue);
        IERC20(result.token).safeTransfer(result.recipient, result.amount);
        emit Unlocked(result.amount, result.recipient);
    }

    function _decodeBurnResult(bytes memory data) internal pure returns(BurnResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.amount = borshData.decodeU128();
        bytes20 token = borshData.decodeBytes20();
        result.token = address(uint160(token));
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
    }
}
