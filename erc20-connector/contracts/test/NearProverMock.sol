pragma solidity ^0.8;

import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";

contract NearProverMock is INearProver {
    function proveOutcome(bytes memory /*proofData*/, uint64 /*blockHeight*/) override public pure returns(bool) {
        return true;
    }
}
