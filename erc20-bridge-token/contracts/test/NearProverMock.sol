// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";

contract NearProverMock is INearProver {
    function proveOutcome(bytes memory /*proofData*/, uint64 /*blockHeight*/) override external pure returns(bool) {
        return true;
    }
}
