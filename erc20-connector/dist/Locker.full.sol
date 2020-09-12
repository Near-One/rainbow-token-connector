
// File: solidity-stringutils/strings.sol

/*
 * @title String & slice utility library for Solidity contracts.
 * @author Nick Johnson <arachnid@notdot.net>
 *
 * @dev Functionality in this library is largely implemented using an
 *      abstraction called a 'slice'. A slice represents a part of a string -
 *      anything from the entire string to a single character, or even no
 *      characters at all (a 0-length slice). Since a slice only has to specify
 *      an offset and a length, copying and manipulating slices is a lot less
 *      expensive than copying and manipulating the strings they reference.
 *
 *      To further reduce gas costs, most functions on slice that need to return
 *      a slice modify the original one instead of allocating a new one; for
 *      instance, `s.split(".")` will return the text up to the first '.',
 *      modifying s to only contain the remainder of the string after the '.'.
 *      In situations where you do not want to modify the original slice, you
 *      can make a copy first with `.copy()`, for example:
 *      `s.copy().split(".")`. Try and avoid using this idiom in loops; since
 *      Solidity has no memory management, it will result in allocating many
 *      short-lived slices that are later discarded.
 *
 *      Functions that return two slices come in two versions: a non-allocating
 *      version that takes the second slice as an argument, modifying it in
 *      place, and an allocating version that allocates and returns the second
 *      slice; see `nextRune` for example.
 *
 *      Functions that have to copy string data will return strings rather than
 *      slices; these can be cast back to slices for further processing if
 *      required.
 *
 *      For convenience, some functions are provided with non-modifying
 *      variants that create a new slice and return both; for instance,
 *      `s.splitNew('.')` leaves s unmodified, and returns two values
 *      corresponding to the left and right parts of the string.
 */

pragma solidity >0.4.13 <0.7.0;

library strings {
    struct slice {
        uint _len;
        uint _ptr;
    }

    function memcpy(uint dest, uint src, uint len) private pure {
        // Copy word-length chunks while possible
        for(; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

    /*
     * @dev Returns a slice containing the entire string.
     * @param self The string to make a slice from.
     * @return A newly allocated slice containing the entire string.
     */
    function toSlice(string memory self) internal pure returns (slice memory) {
        uint ptr;
        assembly {
            ptr := add(self, 0x20)
        }
        return slice(bytes(self).length, ptr);
    }

    /*
     * @dev Returns the length of a null-terminated bytes32 string.
     * @param self The value to find the length of.
     * @return The length of the string, from 0 to 32.
     */
    function len(bytes32 self) internal pure returns (uint) {
        uint ret;
        if (self == 0)
            return 0;
        if (uint(self) & 0xffffffffffffffffffffffffffffffff == 0) {
            ret += 16;
            self = bytes32(uint(self) / 0x100000000000000000000000000000000);
        }
        if (uint(self) & 0xffffffffffffffff == 0) {
            ret += 8;
            self = bytes32(uint(self) / 0x10000000000000000);
        }
        if (uint(self) & 0xffffffff == 0) {
            ret += 4;
            self = bytes32(uint(self) / 0x100000000);
        }
        if (uint(self) & 0xffff == 0) {
            ret += 2;
            self = bytes32(uint(self) / 0x10000);
        }
        if (uint(self) & 0xff == 0) {
            ret += 1;
        }
        return 32 - ret;
    }

    /*
     * @dev Returns a slice containing the entire bytes32, interpreted as a
     *      null-terminated utf-8 string.
     * @param self The bytes32 value to convert to a slice.
     * @return A new slice containing the value of the input argument up to the
     *         first null.
     */
    function toSliceB32(bytes32 self) internal pure returns (slice memory ret) {
        // Allocate space for `self` in memory, copy it there, and point ret at it
        assembly {
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x20))
            mstore(ptr, self)
            mstore(add(ret, 0x20), ptr)
        }
        ret._len = len(self);
    }

    /*
     * @dev Returns a new slice containing the same data as the current slice.
     * @param self The slice to copy.
     * @return A new slice containing the same data as `self`.
     */
    function copy(slice memory self) internal pure returns (slice memory) {
        return slice(self._len, self._ptr);
    }

    /*
     * @dev Copies a slice to a new string.
     * @param self The slice to copy.
     * @return A newly allocated string containing the slice's text.
     */
    function toString(slice memory self) internal pure returns (string memory) {
        string memory ret = new string(self._len);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        memcpy(retptr, self._ptr, self._len);
        return ret;
    }

    /*
     * @dev Returns the length in runes of the slice. Note that this operation
     *      takes time proportional to the length of the slice; avoid using it
     *      in loops, and call `slice.empty()` if you only need to know whether
     *      the slice is empty or not.
     * @param self The slice to operate on.
     * @return The length of the slice in runes.
     */
    function len(slice memory self) internal pure returns (uint l) {
        // Starting at ptr-31 means the LSB will be the byte we care about
        uint ptr = self._ptr - 31;
        uint end = ptr + self._len;
        for (l = 0; ptr < end; l++) {
            uint8 b;
            assembly { b := and(mload(ptr), 0xFF) }
            if (b < 0x80) {
                ptr += 1;
            } else if(b < 0xE0) {
                ptr += 2;
            } else if(b < 0xF0) {
                ptr += 3;
            } else if(b < 0xF8) {
                ptr += 4;
            } else if(b < 0xFC) {
                ptr += 5;
            } else {
                ptr += 6;
            }
        }
    }

    /*
     * @dev Returns true if the slice is empty (has a length of 0).
     * @param self The slice to operate on.
     * @return True if the slice is empty, False otherwise.
     */
    function empty(slice memory self) internal pure returns (bool) {
        return self._len == 0;
    }

    /*
     * @dev Returns a positive number if `other` comes lexicographically after
     *      `self`, a negative number if it comes before, or zero if the
     *      contents of the two slices are equal. Comparison is done per-rune,
     *      on unicode codepoints.
     * @param self The first slice to compare.
     * @param other The second slice to compare.
     * @return The result of the comparison.
     */
    function compare(slice memory self, slice memory other) internal pure returns (int) {
        uint shortest = self._len;
        if (other._len < self._len)
            shortest = other._len;

        uint selfptr = self._ptr;
        uint otherptr = other._ptr;
        for (uint idx = 0; idx < shortest; idx += 32) {
            uint a;
            uint b;
            assembly {
                a := mload(selfptr)
                b := mload(otherptr)
            }
            if (a != b) {
                // Mask out irrelevant bytes and check again
                uint256 mask = uint256(-1); // 0xffff...
                if(shortest < 32) {
                  mask = ~(2 ** (8 * (32 - shortest + idx)) - 1);
                }
                uint256 diff = (a & mask) - (b & mask);
                if (diff != 0)
                    return int(diff);
            }
            selfptr += 32;
            otherptr += 32;
        }
        return int(self._len) - int(other._len);
    }

    /*
     * @dev Returns true if the two slices contain the same text.
     * @param self The first slice to compare.
     * @param self The second slice to compare.
     * @return True if the slices are equal, false otherwise.
     */
    function equals(slice memory self, slice memory other) internal pure returns (bool) {
        return compare(self, other) == 0;
    }

    /*
     * @dev Extracts the first rune in the slice into `rune`, advancing the
     *      slice to point to the next rune and returning `self`.
     * @param self The slice to operate on.
     * @param rune The slice that will contain the first rune.
     * @return `rune`.
     */
    function nextRune(slice memory self, slice memory rune) internal pure returns (slice memory) {
        rune._ptr = self._ptr;

        if (self._len == 0) {
            rune._len = 0;
            return rune;
        }

        uint l;
        uint b;
        // Load the first byte of the rune into the LSBs of b
        assembly { b := and(mload(sub(mload(add(self, 32)), 31)), 0xFF) }
        if (b < 0x80) {
            l = 1;
        } else if(b < 0xE0) {
            l = 2;
        } else if(b < 0xF0) {
            l = 3;
        } else {
            l = 4;
        }

        // Check for truncated codepoints
        if (l > self._len) {
            rune._len = self._len;
            self._ptr += self._len;
            self._len = 0;
            return rune;
        }

        self._ptr += l;
        self._len -= l;
        rune._len = l;
        return rune;
    }

    /*
     * @dev Returns the first rune in the slice, advancing the slice to point
     *      to the next rune.
     * @param self The slice to operate on.
     * @return A slice containing only the first rune from `self`.
     */
    function nextRune(slice memory self) internal pure returns (slice memory ret) {
        nextRune(self, ret);
    }

    /*
     * @dev Returns the number of the first codepoint in the slice.
     * @param self The slice to operate on.
     * @return The number of the first codepoint in the slice.
     */
    function ord(slice memory self) internal pure returns (uint ret) {
        if (self._len == 0) {
            return 0;
        }

        uint word;
        uint length;
        uint divisor = 2 ** 248;

        // Load the rune into the MSBs of b
        assembly { word:= mload(mload(add(self, 32))) }
        uint b = word / divisor;
        if (b < 0x80) {
            ret = b;
            length = 1;
        } else if(b < 0xE0) {
            ret = b & 0x1F;
            length = 2;
        } else if(b < 0xF0) {
            ret = b & 0x0F;
            length = 3;
        } else {
            ret = b & 0x07;
            length = 4;
        }

        // Check for truncated codepoints
        if (length > self._len) {
            return 0;
        }

        for (uint i = 1; i < length; i++) {
            divisor = divisor / 256;
            b = (word / divisor) & 0xFF;
            if (b & 0xC0 != 0x80) {
                // Invalid UTF-8 sequence
                return 0;
            }
            ret = (ret * 64) | (b & 0x3F);
        }

        return ret;
    }

    /*
     * @dev Returns the keccak-256 hash of the slice.
     * @param self The slice to hash.
     * @return The hash of the slice.
     */
    function keccak(slice memory self) internal pure returns (bytes32 ret) {
        assembly {
            ret := keccak256(mload(add(self, 32)), mload(self))
        }
    }

    /*
     * @dev Returns true if `self` starts with `needle`.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return True if the slice starts with the provided text, false otherwise.
     */
    function startsWith(slice memory self, slice memory needle) internal pure returns (bool) {
        if (self._len < needle._len) {
            return false;
        }

        if (self._ptr == needle._ptr) {
            return true;
        }

        bool equal;
        assembly {
            let length := mload(needle)
            let selfptr := mload(add(self, 0x20))
            let needleptr := mload(add(needle, 0x20))
            equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
        }
        return equal;
    }

    /*
     * @dev If `self` starts with `needle`, `needle` is removed from the
     *      beginning of `self`. Otherwise, `self` is unmodified.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return `self`
     */
    function beyond(slice memory self, slice memory needle) internal pure returns (slice memory) {
        if (self._len < needle._len) {
            return self;
        }

        bool equal = true;
        if (self._ptr != needle._ptr) {
            assembly {
                let length := mload(needle)
                let selfptr := mload(add(self, 0x20))
                let needleptr := mload(add(needle, 0x20))
                equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
            }
        }

        if (equal) {
            self._len -= needle._len;
            self._ptr += needle._len;
        }

        return self;
    }

    /*
     * @dev Returns true if the slice ends with `needle`.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return True if the slice starts with the provided text, false otherwise.
     */
    function endsWith(slice memory self, slice memory needle) internal pure returns (bool) {
        if (self._len < needle._len) {
            return false;
        }

        uint selfptr = self._ptr + self._len - needle._len;

        if (selfptr == needle._ptr) {
            return true;
        }

        bool equal;
        assembly {
            let length := mload(needle)
            let needleptr := mload(add(needle, 0x20))
            equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
        }

        return equal;
    }

    /*
     * @dev If `self` ends with `needle`, `needle` is removed from the
     *      end of `self`. Otherwise, `self` is unmodified.
     * @param self The slice to operate on.
     * @param needle The slice to search for.
     * @return `self`
     */
    function until(slice memory self, slice memory needle) internal pure returns (slice memory) {
        if (self._len < needle._len) {
            return self;
        }

        uint selfptr = self._ptr + self._len - needle._len;
        bool equal = true;
        if (selfptr != needle._ptr) {
            assembly {
                let length := mload(needle)
                let needleptr := mload(add(needle, 0x20))
                equal := eq(keccak256(selfptr, length), keccak256(needleptr, length))
            }
        }

        if (equal) {
            self._len -= needle._len;
        }

        return self;
    }

    // Returns the memory address of the first byte of the first occurrence of
    // `needle` in `self`, or the first byte after `self` if not found.
    function findPtr(uint selflen, uint selfptr, uint needlelen, uint needleptr) private pure returns (uint) {
        uint ptr = selfptr;
        uint idx;

        if (needlelen <= selflen) {
            if (needlelen <= 32) {
                bytes32 mask = bytes32(~(2 ** (8 * (32 - needlelen)) - 1));

                bytes32 needledata;
                assembly { needledata := and(mload(needleptr), mask) }

                uint end = selfptr + selflen - needlelen;
                bytes32 ptrdata;
                assembly { ptrdata := and(mload(ptr), mask) }

                while (ptrdata != needledata) {
                    if (ptr >= end)
                        return selfptr + selflen;
                    ptr++;
                    assembly { ptrdata := and(mload(ptr), mask) }
                }
                return ptr;
            } else {
                // For long needles, use hashing
                bytes32 hash;
                assembly { hash := keccak256(needleptr, needlelen) }

                for (idx = 0; idx <= selflen - needlelen; idx++) {
                    bytes32 testHash;
                    assembly { testHash := keccak256(ptr, needlelen) }
                    if (hash == testHash)
                        return ptr;
                    ptr += 1;
                }
            }
        }
        return selfptr + selflen;
    }

    // Returns the memory address of the first byte after the last occurrence of
    // `needle` in `self`, or the address of `self` if not found.
    function rfindPtr(uint selflen, uint selfptr, uint needlelen, uint needleptr) private pure returns (uint) {
        uint ptr;

        if (needlelen <= selflen) {
            if (needlelen <= 32) {
                bytes32 mask = bytes32(~(2 ** (8 * (32 - needlelen)) - 1));

                bytes32 needledata;
                assembly { needledata := and(mload(needleptr), mask) }

                ptr = selfptr + selflen - needlelen;
                bytes32 ptrdata;
                assembly { ptrdata := and(mload(ptr), mask) }

                while (ptrdata != needledata) {
                    if (ptr <= selfptr)
                        return selfptr;
                    ptr--;
                    assembly { ptrdata := and(mload(ptr), mask) }
                }
                return ptr + needlelen;
            } else {
                // For long needles, use hashing
                bytes32 hash;
                assembly { hash := keccak256(needleptr, needlelen) }
                ptr = selfptr + (selflen - needlelen);
                while (ptr >= selfptr) {
                    bytes32 testHash;
                    assembly { testHash := keccak256(ptr, needlelen) }
                    if (hash == testHash)
                        return ptr + needlelen;
                    ptr -= 1;
                }
            }
        }
        return selfptr;
    }

    /*
     * @dev Modifies `self` to contain everything from the first occurrence of
     *      `needle` to the end of the slice. `self` is set to the empty slice
     *      if `needle` is not found.
     * @param self The slice to search and modify.
     * @param needle The text to search for.
     * @return `self`.
     */
    function find(slice memory self, slice memory needle) internal pure returns (slice memory) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr);
        self._len -= ptr - self._ptr;
        self._ptr = ptr;
        return self;
    }

    /*
     * @dev Modifies `self` to contain the part of the string from the start of
     *      `self` to the end of the first occurrence of `needle`. If `needle`
     *      is not found, `self` is set to the empty slice.
     * @param self The slice to search and modify.
     * @param needle The text to search for.
     * @return `self`.
     */
    function rfind(slice memory self, slice memory needle) internal pure returns (slice memory) {
        uint ptr = rfindPtr(self._len, self._ptr, needle._len, needle._ptr);
        self._len = ptr - self._ptr;
        return self;
    }

    /*
     * @dev Splits the slice, setting `self` to everything after the first
     *      occurrence of `needle`, and `token` to everything before it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and `token` is set to the entirety of `self`.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @param token An output parameter to which the first token is written.
     * @return `token`.
     */
    function split(slice memory self, slice memory needle, slice memory token) internal pure returns (slice memory) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr);
        token._ptr = self._ptr;
        token._len = ptr - self._ptr;
        if (ptr == self._ptr + self._len) {
            // Not found
            self._len = 0;
        } else {
            self._len -= token._len + needle._len;
            self._ptr = ptr + needle._len;
        }
        return token;
    }

    /*
     * @dev Splits the slice, setting `self` to everything after the first
     *      occurrence of `needle`, and returning everything before it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and the entirety of `self` is returned.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @return The part of `self` up to the first occurrence of `delim`.
     */
    function split(slice memory self, slice memory needle) internal pure returns (slice memory token) {
        split(self, needle, token);
    }

    /*
     * @dev Splits the slice, setting `self` to everything before the last
     *      occurrence of `needle`, and `token` to everything after it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and `token` is set to the entirety of `self`.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @param token An output parameter to which the first token is written.
     * @return `token`.
     */
    function rsplit(slice memory self, slice memory needle, slice memory token) internal pure returns (slice memory) {
        uint ptr = rfindPtr(self._len, self._ptr, needle._len, needle._ptr);
        token._ptr = ptr;
        token._len = self._len - (ptr - self._ptr);
        if (ptr == self._ptr) {
            // Not found
            self._len = 0;
        } else {
            self._len -= token._len + needle._len;
        }
        return token;
    }

    /*
     * @dev Splits the slice, setting `self` to everything before the last
     *      occurrence of `needle`, and returning everything after it. If
     *      `needle` does not occur in `self`, `self` is set to the empty slice,
     *      and the entirety of `self` is returned.
     * @param self The slice to split.
     * @param needle The text to search for in `self`.
     * @return The part of `self` after the last occurrence of `delim`.
     */
    function rsplit(slice memory self, slice memory needle) internal pure returns (slice memory token) {
        rsplit(self, needle, token);
    }

    /*
     * @dev Counts the number of nonoverlapping occurrences of `needle` in `self`.
     * @param self The slice to search.
     * @param needle The text to search for in `self`.
     * @return The number of occurrences of `needle` found in `self`.
     */
    function count(slice memory self, slice memory needle) internal pure returns (uint cnt) {
        uint ptr = findPtr(self._len, self._ptr, needle._len, needle._ptr) + needle._len;
        while (ptr <= self._ptr + self._len) {
            cnt++;
            ptr = findPtr(self._len - (ptr - self._ptr), ptr, needle._len, needle._ptr) + needle._len;
        }
    }

    /*
     * @dev Returns True if `self` contains `needle`.
     * @param self The slice to search.
     * @param needle The text to search for in `self`.
     * @return True if `needle` is found in `self`, false otherwise.
     */
    function contains(slice memory self, slice memory needle) internal pure returns (bool) {
        return rfindPtr(self._len, self._ptr, needle._len, needle._ptr) != self._ptr;
    }

    /*
     * @dev Returns a newly allocated string containing the concatenation of
     *      `self` and `other`.
     * @param self The first slice to concatenate.
     * @param other The second slice to concatenate.
     * @return The concatenation of the two strings.
     */
    function concat(slice memory self, slice memory other) internal pure returns (string memory) {
        string memory ret = new string(self._len + other._len);
        uint retptr;
        assembly { retptr := add(ret, 32) }
        memcpy(retptr, self._ptr, self._len);
        memcpy(retptr + self._len, other._ptr, other._len);
        return ret;
    }

    /*
     * @dev Joins an array of slices, using `self` as a delimiter, returning a
     *      newly allocated string.
     * @param self The delimiter to use.
     * @param parts A list of slices to join.
     * @return A newly allocated string containing all the slices in `parts`,
     *         joined with `self`.
     */
    function join(slice memory self, slice[] memory parts) internal pure returns (string memory) {
        if (parts.length == 0)
            return "";

        uint length = self._len * (parts.length - 1);
        for(uint i = 0; i < parts.length; i++)
            length += parts[i]._len;

        string memory ret = new string(length);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        for(uint i = 0; i < parts.length; i++) {
            memcpy(retptr, parts[i]._ptr, parts[i]._len);
            retptr += parts[i]._len;
            if (i < parts.length - 1) {
                memcpy(retptr, self._ptr, self._len);
                retptr += self._len;
            }
        }

        return ret;
    }
}

// File: rainbow-bridge-sol/nearprover/contracts/INearProver.sol

pragma solidity ^0.5.0;

interface INearProver {
    function proveOutcome(bytes calldata proofData, uint64 blockHeight) external view returns(bool);
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
        require(data.raw.length >= data.offset + size, "Borsh: Out of range");
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

    function decodeBytes20(Data memory data) internal pure shift(data, 20) returns(bytes20 value) {
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
    using strings for *;

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

        strings.slice memory executorIdSlice = string(fullOutcomeProof.outcome_proof.outcome_with_id.outcome.executor_id).toSlice();
        strings.slice memory delim = ".".toSlice();
        require(executorIdSlice.count(delim) == 1, string(fullOutcomeProof.outcome_proof.outcome_with_id.outcome.executor_id));
        strings.slice memory part;
        executorIdSlice.split(delim, part);
        executorIdSlice.split(delim, part);

        require(keccak256(bytes(part.toString())) == keccak256(nearTokenFactory_),
        "Can only unlock tokens from the linked mintable fungible token on Near blockchain.");

        result = fullOutcomeProof.outcome_proof.outcome_with_id.outcome.status;
        require(!result.failed, "Cannot use failed execution outcome for unlocking the tokens.");
        require(!result.unknown, "Cannot use unknown execution outcome for unlocking the tokens.");
    }
}
