pragma solidity ^0.8;
import "rainbow-bridge-sol/nearbridge/contracts/Borsh.sol";

library ResultsDecoder {
    using Borsh for Borsh.Data;

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

    function decodeLockResult(bytes memory data) external pure returns(LockResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.token = string(borshData.decodeBytes());
        result.amount = borshData.decodeU128();
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
        borshData.done();
    }
       function decodeMetadataResult(bytes memory data) external pure returns(MetadataResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.token = string(borshData.decodeBytes());
        result.name = string(borshData.decodeBytes());
        result.symbol = string(borshData.decodeBytes());
        result.decimals = borshData.decodeU8();
        result.blockHeight = borshData.decodeU64();
        borshData.done();
    }
}