use crate::prover::EthAddress;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{Balance, BlockHeight};

pub type ResultPrefix = [u8; 32];

/// This prefix value is computed as: `keccak256(b"ResultType.Withdraw").as_slice()`
pub const RESULT_PREFIX_WITHDRAW: ResultPrefix = [
    246, 181, 82, 1, 204, 142, 13, 135, 141, 218, 111, 185, 98, 41, 84, 186, 141, 37, 252, 127, 56,
    255, 227, 34, 202, 249, 14, 225, 115, 248, 131, 171,
];

/// This prefix value is computed as: `keccak256(b"ResultType.Lock").as_slice()`
pub const RESULT_PREFIX_LOCK: ResultPrefix = [
    10, 158, 184, 119, 69, 133, 121, 219, 206, 131, 234, 87, 213, 86, 190, 80, 209, 195, 22, 11,
    181, 241, 113, 159, 177, 114, 189, 51, 0, 172, 134, 35,
];

/// This prefix value is computed as: `keccak256(b"ResultType.Metadata").as_slice()`
pub const RESULT_PREFIX_METADATA: ResultPrefix = [
    179, 21, 212, 214, 232, 242, 53, 245, 250, 187, 11, 26, 15, 17, 133, 7, 246, 200, 84, 47, 174,
    142, 26, 149, 102, 171, 230, 7, 98, 4, 124, 22,
];

#[derive(Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Withdraw {
    #[cfg(feature = "result_with_prefix")]
    pub prefix: ResultPrefix,
    pub amount: Balance,
    pub token: EthAddress,
    pub recipient: EthAddress,
}

impl Withdraw {
    pub fn new(amount: Balance, token: EthAddress, recipient: EthAddress) -> Self {
        Self {
            #[cfg(feature = "result_with_prefix")]
            prefix: RESULT_PREFIX_WITHDRAW,
            amount,
            token,
            recipient,
        }
    }
}

#[derive(Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Lock {
    #[cfg(feature = "result_with_prefix")]
    pub prefix: ResultPrefix,
    pub token: String,
    pub amount: Balance,
    pub recipient: EthAddress,
}

impl Lock {
    pub fn new(token: String, amount: Balance, recipient: EthAddress) -> Self {
        Self {
            #[cfg(feature = "result_with_prefix")]
            prefix: RESULT_PREFIX_LOCK,
            token,
            amount,
            recipient,
        }
    }
}

#[derive(Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Metadata {
    #[cfg(feature = "result_with_prefix")]
    pub prefix: ResultPrefix,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub block_height: BlockHeight,
}

impl Metadata {
    pub fn new(
        token: String,
        name: String,
        symbol: String,
        decimals: u8,
        block_height: BlockHeight,
    ) -> Self {
        Self {
            #[cfg(feature = "result_with_prefix")]
            prefix: RESULT_PREFIX_METADATA,
            token,
            name,
            symbol,
            decimals,
            block_height,
        }
    }
}

#[test]
fn generate_result_prefixs() {
    assert_eq!(
        RESULT_PREFIX_WITHDRAW,
        near_sdk::env::keccak256(b"ResultType.Withdraw").as_slice()
    );
    assert_eq!(
        RESULT_PREFIX_LOCK,
        near_sdk::env::keccak256(b"ResultType.Lock").as_slice()
    );
    assert_eq!(
        RESULT_PREFIX_METADATA,
        near_sdk::env::keccak256(b"ResultType.Metadata").as_slice()
    );

    assert_eq!(
        "f6b55201cc8e0d878dda6fb9622954ba8d25fc7f38ffe322caf90ee173f883ab",
        hex::encode(RESULT_PREFIX_WITHDRAW)
    );
    assert_eq!(
        "0a9eb877458579dbce83ea57d556be50d1c3160bb5f1719fb172bd3300ac8623",
        hex::encode(RESULT_PREFIX_LOCK)
    );
    assert_eq!(
        "b315d4d6e8f235f5fabb0b1a0f118507f6c8542fae8e1a9566abe60762047c16",
        hex::encode(RESULT_PREFIX_METADATA)
    );
}
