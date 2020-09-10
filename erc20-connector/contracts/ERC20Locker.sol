pragma solidity ^0.5.0;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "rainbow-bridge-sol/nearprover/contracts/INearProver.sol";
import "rainbow-bridge-sol/nearprover/contracts/ProofDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/NearDecoder.sol";
import "rainbow-bridge-sol/nearbridge/contracts/Borsh.sol";
import "./Locker.sol";

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
        address token;
        uint128 amount;
        address recipient;
    }

    function lockToken(address ethToken, uint256 amount, string memory accountId) public {
        IERC20(ethToken).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(address(ethToken), msg.sender, amount, accountId);
    }

    function unlockToken(bytes memory proofData, uint64 proofBlockHeight) public {
        ProofDecoder.ExecutionStatus memory status = _parseUnlockEvent(proofData, proofBlockHeight);
        BurnResult memory result = _decodeBurnResult(status.successValue);
        IERC20(result.token).safeTransfer(result.recipient, result.amount);
        emit Unlocked(result.amount, result.recipient);
    }

    function _decodeBurnResult(bytes memory data) internal pure returns(BurnResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.amount = borshData.decodeU128();
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
    }
}
