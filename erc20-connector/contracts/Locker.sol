pragma solidity ^0.5.0;
import "solidity-stringutils/strings.sol";

import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";
import "rainbow-bridge-sol/nearprover/contracts/ProofDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/NearDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/Borsh.sol";

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
