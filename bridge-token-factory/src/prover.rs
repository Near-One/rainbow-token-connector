use borsh::{BorshDeserialize, BorshSerialize};
//use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{ext_contract, AccountId, Balance};

use eth_types::*;
use ethabi::{Event, EventParam, Hash, ParamType, RawLog};
use hex::ToHex;

#[ext_contract(ext_prover)]
pub trait Prover {
    #[result_serializer(borsh)]
    fn verify_log_entry(
        &self,
        #[serializer(borsh)] log_index: u64,
        #[serializer(borsh)] log_entry_data: Vec<u8>,
        #[serializer(borsh)] receipt_index: u64,
        #[serializer(borsh)] receipt_data: Vec<u8>,
        #[serializer(borsh)] header_data: Vec<u8>,
        #[serializer(borsh)] proof: Vec<Vec<u8>>,
        #[serializer(borsh)] skip_bridge_call: bool,
    ) -> bool;
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Proof {
    pub log_index: u64,
    pub log_entry_data: Vec<u8>,
    pub receipt_index: u64,
    pub receipt_data: Vec<u8>,
    pub header_data: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

/// Data that was emitted by the Ethereum event.
pub struct EthEventData {
    pub locker_address: [u8; 20],
    pub token: String,
    pub sender: String,
    pub amount: Balance,
    pub recipient: AccountId,
}

impl EthEventData {
    /// Parse raw log entry data.
    pub fn from_log_entry_data(data: &[u8]) -> Self {
        let event = Event {
            name: "Locked".to_string(),
            inputs: vec![
                EventParam {
                    name: "token".to_string(),
                    kind: ParamType::Address,
                    indexed: true,
                },
                EventParam {
                    name: "sender".to_string(),
                    kind: ParamType::Address,
                    indexed: true,
                },
                EventParam {
                    name: "amount".to_string(),
                    kind: ParamType::Uint(256),
                    indexed: false,
                },
                EventParam {
                    name: "accountId".to_string(),
                    kind: ParamType::String,
                    indexed: false,
                },
            ],
            anonymous: false,
        };

        let log_entry: LogEntry = rlp::decode(data).unwrap();
        let locker_address = (log_entry.address.clone().0).0;
        let raw_log = RawLog {
            topics: log_entry
                .topics
                .iter()
                .map(|h| Hash::from(&((h.0).0)))
                .collect(),
            data: log_entry.data.clone(),
        };
        let log = event.parse_log(raw_log).unwrap();
        let token = log.params[0].value.clone().to_address().unwrap().0;
        let token = (&token).encode_hex::<String>();
        let sender = log.params[1].value.clone().to_address().unwrap().0;
        let sender = (&sender).encode_hex::<String>();
        let amount = log.params[2].value.clone().to_uint().unwrap().as_u128();
        let recipient = log.params[3].value.clone().to_string().unwrap();
        Self {
            locker_address,
            token,
            sender,
            amount,
            recipient,
        }
    }
}

impl std::fmt::Display for EthEventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token: {}; sender: {}; amount: {}; recipient: {}",
            self.token, self.sender, self.amount, self.recipient
        )
    }
}
