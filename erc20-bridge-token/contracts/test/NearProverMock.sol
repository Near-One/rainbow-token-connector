// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";

contract NearProverMock is INearProver {
    function proveOutcome(
        bytes memory /*proofData*/,
        uint64 /*blockHeight*/
    ) external pure override returns (bool) {
        return true;
    }
}
