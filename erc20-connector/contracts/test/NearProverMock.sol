pragma solidity ^0.6.0;

import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";

contract NearProverMock is INearProver {
    function proveOutcome(bytes memory proofData, uint64 blockHeight) public override view returns(bool) {
        return true;
    }
}