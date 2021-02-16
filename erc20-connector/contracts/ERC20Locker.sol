pragma solidity ^0.6;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "rainbow-bridge/contracts/eth/nearprover/contracts/ProofDecoder.sol";
import "rainbow-bridge/contracts/eth/nearbridge/contracts/Borsh.sol";
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
        uint128 amount;
        address token;
        address recipient;
    }

    // ERC20Locker is linked to the bridge token factory on NEAR side.
    // It also links to the prover that it uses to unlock the tokens.
    constructor(bytes memory nearTokenFactory, INearProver prover, address admin) public {
        nearTokenFactory_ = nearTokenFactory;
        prover_ = prover;
        admin_ = admin;
    }

    function lockToken(address ethToken, uint256 amount, string memory accountId) public {
        IERC20(ethToken).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(address(ethToken), msg.sender, amount, accountId);
    }

    function unlockToken(bytes memory proofData, uint64 proofBlockHeight) public {
        ProofDecoder.ExecutionStatus memory status = _parseProof(proofData, proofBlockHeight);
        BurnResult memory result = _decodeBurnResult(status.successValue);
        IERC20(result.token).safeTransfer(result.recipient, result.amount);
        emit Unlocked(result.amount, result.recipient);
    }

    function _decodeBurnResult(bytes memory data) internal pure returns(BurnResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        uint8 flag = borshData.decodeU8();
        require(flag == 0, "ERR_NOT_WITHDRAW_RESULT");
        result.amount = borshData.decodeU128();
        bytes20 token = borshData.decodeBytes20();
        result.token = address(uint160(token));
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
    }

    // tokenFallback implements the ContractReceiver interface from ERC223-token-standard.
    // This allows to support ERC223 tokens with no extra cost.
    // The function always passes: we don't need to make any decision and the contract always
    // accept token transfers transfer.
    function tokenFallback(address _from, uint _value, bytes _data) public pure {}

    address public admin_;

    modifier onlyAdmin {
        require(msg.sender == admin_);
        _;
    }

    function adminTransfer(IERC20 token, address destination, uint amount) public onlyAdmin {
        token.safeTransfer(destination, amount);
    }

    function adminDelegatecall(address target, bytes memory data) public onlyAdmin returns(bytes memory) {
        (bool success, bytes memory rdata) = target.delegatecall(data);
        require(success);
        return rdata;
    }
}
