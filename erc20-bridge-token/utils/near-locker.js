const { Web3, BorshContract, readerToHex } = require("rainbow-bridge-utils");

const borshSchema = {
    bool: {
        kind: 'function',
        ser: (b) => Buffer.from(Web3.utils.hexToBytes(b ? '0x01' : '0x00')),
        deser: (z) => readerToHex(1)(z) === '0x01'
    },
    Proof: {
        kind: 'struct',
        fields: [
            ['log_index', 'u64'],
            ['log_entry_data', ['u8']],
            ['receipt_index', 'u64'],
            ['receipt_data', ['u8']],
            ['header_data', ['u8']],
            ['proof', [['u8']]]
        ]
    }
}

class NearTokenLocker extends BorshContract {
    constructor(account, contractId) {
        super(borshSchema, account, contractId, {
            viewMethods: [],
            changeMethods: [
                {
                    methodName: 'withdraw',
                    inputFieldType: 'Proof',
                    outputFieldType: null
                }
            ]
        })
    }
}

exports.NearTokenLocker = NearTokenLocker;
exports.borshSchema = borshSchema;