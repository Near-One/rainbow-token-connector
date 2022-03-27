use admin_controlled::{Mask};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{Balance, Gas, AccountId, BlockHeight};
use prover::EthAddress;

pub mod prover;

pub const NO_DEPOSIT: Balance = 0;

pub const PAUSE_DEPOSIT: Mask = 1 << 1;

/// Gas to call verify_log_entry on prover.
pub const VERIFY_LOG_ENTRY_GAS: Gas = 50_000_000_000_000;

/// Gas to call ft_transfer_call when the target of deposit is a contract
pub const FT_TRANSFER_CALL_GAS: Gas = 80_000_000_000_000;

/// Gas to call ft_transfer
pub const FT_TRANSFER_GAS: Gas = 20_000_000_000_000;

#[derive(Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum ResultType {
    Withdraw {
        amount: Balance,
        token: EthAddress,
        recipient: EthAddress,
    },
    Lock {
        token: String,
        amount: Balance,
        recipient: EthAddress,
    },
    Metadata {
        token: String,
        name: String,
        symbol: String,
        decimals: u8,
        block_height: BlockHeight,
    }
}

pub struct Recipient {
    pub target: AccountId,
    pub message: Option<String>,
}

/// `recipient` is the target account id receiving current ERC-20 tokens.
///
/// If `recipient` doesn't contain a semicolon (:) then it is interpreted as a NEAR account id
/// and token are minted as NEP-141 directly on `recipient` account id.
///
/// Otherwise, the format expected is: <target_address>:<message>
///
/// @target_address: Account id of the contract to transfer current funds
/// @message: Free form message to be send to the target using ft_transfer_call
///
/// The final message sent to the `target_address` has the format:
///
/// <message>
///
/// Where `message` is the free form string that was passed.
pub fn parse_recipient(recipient: String) -> Recipient {
    if recipient.contains(':') {
        let mut iter = recipient.split(':');
        let target = iter.next().unwrap().into();
        let message = iter.collect::<Vec<&str>>().join(":");

        Recipient {
            target,
            message: Some(message),
        }
    } else {
        Recipient {
            target: recipient,
            message: None,
        }
    }
}
