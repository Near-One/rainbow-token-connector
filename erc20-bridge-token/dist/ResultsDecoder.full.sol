// Sources flattened with hardhat v2.10.1 https://hardhat.org

// File rainbow-bridge-sol/nearbridge/contracts/Utils.sol@v2.0.1

pragma solidity ^0.8;

library Utils {
    function swapBytes2(uint16 v) internal pure returns (uint16) {
        return (v << 8) | (v >> 8);
    }

    function swapBytes4(uint32 v) internal pure returns (uint32) {
        v = ((v & 0x00ff00ff) << 8) | ((v & 0xff00ff00) >> 8);
        return (v << 16) | (v >> 16);
    }

    function swapBytes8(uint64 v) internal pure returns (uint64) {
        v = ((v & 0x00ff00ff00ff00ff) << 8) | ((v & 0xff00ff00ff00ff00) >> 8);
        v = ((v & 0x0000ffff0000ffff) << 16) | ((v & 0xffff0000ffff0000) >> 16);
        return (v << 32) | (v >> 32);
    }

    function swapBytes16(uint128 v) internal pure returns (uint128) {
        v = ((v & 0x00ff00ff00ff00ff00ff00ff00ff00ff) << 8) | ((v & 0xff00ff00ff00ff00ff00ff00ff00ff00) >> 8);
        v = ((v & 0x0000ffff0000ffff0000ffff0000ffff) << 16) | ((v & 0xffff0000ffff0000ffff0000ffff0000) >> 16);
        v = ((v & 0x00000000ffffffff00000000ffffffff) << 32) | ((v & 0xffffffff00000000ffffffff00000000) >> 32);
        return (v << 64) | (v >> 64);
    }

    function swapBytes32(uint256 v) internal pure returns (uint256) {
        v =
            ((v & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8) |
            ((v & 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00) >> 8);
        v =
            ((v & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16) |
            ((v & 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000) >> 16);
        v =
            ((v & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32) |
            ((v & 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000) >> 32);
        v =
            ((v & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff) << 64) |
            ((v & 0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000) >> 64);
        return (v << 128) | (v >> 128);
    }

    function readMemory(uint ptr) internal pure returns (uint res) {
        assembly {
            res := mload(ptr)
        }
    }

    function writeMemory(uint ptr, uint value) internal pure {
        assembly {
            mstore(ptr, value)
        }
    }

    function memoryToBytes(uint ptr, uint length) internal pure returns (bytes memory res) {
        if (length != 0) {
            assembly {
                // 0x40 is the address of free memory pointer.
                res := mload(0x40)
                let end := add(
                    res,
                    and(add(length, 63), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0)
                )
                // end = res + 32 + 32 * ceil(length / 32).
                mstore(0x40, end)
                mstore(res, length)
                let destPtr := add(res, 32)
                // prettier-ignore
                for { } 1 { } {
                    mstore(destPtr, mload(ptr))
                    destPtr := add(destPtr, 32)
                    if eq(destPtr, end) {
                        break
                    }
                    ptr := add(ptr, 32)
                }
            }
        }
    }

    function keccak256Raw(uint ptr, uint length) internal pure returns (bytes32 res) {
        assembly {
            res := keccak256(ptr, length)
        }
    }

    function sha256Raw(uint ptr, uint length) internal view returns (bytes32 res) {
        assembly {
            // 2 is the address of SHA256 precompiled contract.
            // First 64 bytes of memory can be used as scratch space.
            let ret := staticcall(gas(), 2, ptr, length, 0, 32)
            // If the call to SHA256 precompile ran out of gas, burn any gas that remains.
            // prettier-ignore
            for { } iszero(ret) { } { }
            res := mload(0)
        }
    }
}


// File rainbow-bridge-sol/nearbridge/contracts/Borsh.sol@v2.0.1

pragma solidity ^0.8;

library Borsh {
    using Borsh for Data;

    struct Data {
        uint ptr;
        uint end;
    }

    function from(bytes memory data) internal pure returns (Data memory res) {
        uint ptr;
        assembly {
            ptr := data
        }
        unchecked {
            res.ptr = ptr + 32;
            res.end = res.ptr + Utils.readMemory(ptr);
        }
    }

    // This function assumes that length is reasonably small, so that data.ptr + length will not overflow. In the current code, length is always less than 2^32.
    function requireSpace(Data memory data, uint length) internal pure {
        unchecked {
            require(data.ptr + length <= data.end, "Parse error: unexpected EOI");
        }
    }

    function read(Data memory data, uint length) internal pure returns (bytes32 res) {
        data.requireSpace(length);
        res = bytes32(Utils.readMemory(data.ptr));
        unchecked {
            data.ptr += length;
        }
        return res;
    }

    function done(Data memory data) internal pure {
        require(data.ptr == data.end, "Parse error: EOI expected");
    }

    // Same considerations as for requireSpace.
    function peekKeccak256(Data memory data, uint length) internal pure returns (bytes32) {
        data.requireSpace(length);
        return Utils.keccak256Raw(data.ptr, length);
    }

    // Same considerations as for requireSpace.
    function peekSha256(Data memory data, uint length) internal view returns (bytes32) {
        data.requireSpace(length);
        return Utils.sha256Raw(data.ptr, length);
    }

    function decodeU8(Data memory data) internal pure returns (uint8) {
        return uint8(bytes1(data.read(1)));
    }

    function decodeU16(Data memory data) internal pure returns (uint16) {
        return Utils.swapBytes2(uint16(bytes2(data.read(2))));
    }

    function decodeU32(Data memory data) internal pure returns (uint32) {
        return Utils.swapBytes4(uint32(bytes4(data.read(4))));
    }

    function decodeU64(Data memory data) internal pure returns (uint64) {
        return Utils.swapBytes8(uint64(bytes8(data.read(8))));
    }

    function decodeU128(Data memory data) internal pure returns (uint128) {
        return Utils.swapBytes16(uint128(bytes16(data.read(16))));
    }

    function decodeU256(Data memory data) internal pure returns (uint256) {
        return Utils.swapBytes32(uint256(data.read(32)));
    }

    function decodeBytes20(Data memory data) internal pure returns (bytes20) {
        return bytes20(data.read(20));
    }

    function decodeBytes32(Data memory data) internal pure returns (bytes32) {
        return data.read(32);
    }

    function decodeBool(Data memory data) internal pure returns (bool) {
        uint8 res = data.decodeU8();
        require(res <= 1, "Parse error: invalid bool");
        return res != 0;
    }

    function skipBytes(Data memory data) internal pure {
        uint length = data.decodeU32();
        data.requireSpace(length);
        unchecked {
            data.ptr += length;
        }
    }

    function decodeBytes(Data memory data) internal pure returns (bytes memory res) {
        uint length = data.decodeU32();
        data.requireSpace(length);
        res = Utils.memoryToBytes(data.ptr, length);
        unchecked {
            data.ptr += length;
        }
    }
}


// File contracts/ResultsDecoder.sol

pragma solidity ^0.8;

library ResultsDecoder {
    using Borsh for Borsh.Data;
    bytes32 public constant RESULT_PREFIX_LOCK =
        0x0a9eb877458579dbce83ea57d556be50d1c3160bb5f1719fb172bd3300ac8623;
    bytes32 public constant RESULT_PREFIX_METADATA =
        0xb315d4d6e8f235f5fabb0b1a0f118507f6c8542fae8e1a9566abe60762047c16;

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

    function decodeLockResult(bytes memory data)
        internal
        pure
        returns (LockResult memory result)
    {
        Borsh.Data memory borshData = Borsh.from(data);
        bytes32 prefix = borshData.decodeBytes32();
        require(prefix == RESULT_PREFIX_LOCK, "ERR_INVALID_LOCK_PREFIX");
        result.token = string(borshData.decodeBytes());
        result.amount = borshData.decodeU128();
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
        borshData.done();
    }

    function decodeMetadataResult(bytes memory data)
        internal
        pure
        returns (MetadataResult memory result)
    {
        Borsh.Data memory borshData = Borsh.from(data);
        bytes32 prefix = borshData.decodeBytes32();
        require(
            prefix == RESULT_PREFIX_METADATA,
            "ERR_INVALID_METADATA_PREFIX"
        );
        result.token = string(borshData.decodeBytes());
        result.name = string(borshData.decodeBytes());
        result.symbol = string(borshData.decodeBytes());
        result.decimals = borshData.decodeU8();
        result.blockHeight = borshData.decodeU64();
        borshData.done();
    }
}
