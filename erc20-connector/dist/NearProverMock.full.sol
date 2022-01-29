// Sources flattened with hardhat v2.8.3 https://hardhat.org

// File rainbow-bridge-sol/nearprover/contracts/INearProver.sol@v2.0.1

pragma solidity ^0.8;

interface INearProver {
    function proveOutcome(bytes calldata proofData, uint64 blockHeight) external view returns (bool);
}


// File contracts/test/NearProverMock.sol

pragma solidity ^0.8;

contract NearProverMock is INearProver {
    function proveOutcome(bytes memory proofData, uint64 blockHeight) override public view returns(bool) {
        return true;
    }
}
Done in 0.43s.
