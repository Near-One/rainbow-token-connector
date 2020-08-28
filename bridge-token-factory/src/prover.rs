use std::convert::From;

use borsh::{BorshDeserialize, BorshSerialize};
use eth_types::*;
use ethabi::{Event, EventParam, Hash, ParamType, RawLog, Token};
use ethabi::param_type::Writer;
use hex::ToHex;
//use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{AccountId, Balance, ext_contract};

use tiny_keccak::Keccak;

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

/// Data that was emitted by the Ethereum Locked event.
#[derive(Debug, Eq, PartialEq)]
pub struct EthLockedEvent {
    pub locker_address: [u8; 20],
    pub token: String,
    pub sender: String,
    pub amount: Balance,
    pub recipient: AccountId,
}

impl EthLockedEvent {
    fn event() -> Event {
        Event {
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
        }
    }
    /// Parse raw log entry data.
    pub fn from_log_entry_data(data: &[u8]) -> Self {
        let event = EthLockedEvent::event();
        let log_entry: LogEntry = rlp::decode(data).expect("Invalid RLP");
        let locker_address = (log_entry.address.clone().0).0;
        let raw_log = RawLog {
            topics: log_entry
                .topics
                .iter()
                .map(|h| Hash::from(&((h.0).0)))
                .collect(),
            data: log_entry.data.clone(),
        };
        let log = event.parse_log(raw_log).expect("Failed to parse event log");
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

    pub fn to_log_entry_data(&self) -> Vec<u8> {
        let event = EthLockedEvent::event();
        let token = hex::decode(self.token.clone()).unwrap();
        let sender = hex::decode(self.sender.clone()).unwrap();
        let params: Vec<ParamType> = event.inputs.iter().map(|p| p.kind.clone()).collect();
        let log_entry = LogEntry {
            address: self.locker_address.into(),
            topics: vec![
                long_signature("Locked", &params).0.into(),
                eth_types::H256::from(&token),
                eth_types::H256::from(&sender),
            ],
            data: ethabi::encode(&[
                Token::Uint(self.amount.into()),
                Token::String(self.recipient.clone())
            ]),
        };
        rlp::encode(&log_entry)
    }
}

impl std::fmt::Display for EthLockedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token: {}; sender: {}; amount: {}; recipient: {}",
            self.token, self.sender, self.amount, self.recipient
        )
    }
}

fn long_signature(name: &str, params: &[ParamType]) -> Hash {
    let mut result = [0u8; 32];
    fill_signature(name, params, &mut result);
    result.into()
}

fn fill_signature(name: &str, params: &[ParamType], result: &mut [u8]) {
    let types = params.iter().map(Writer::write).collect::<Vec<String>>().join(",");

    let data: Vec<u8> = From::from(format!("{}({})", name, types).as_str());

    let mut sponge = Keccak::new_keccak256();
    sponge.update(&data);
    sponge.finalize(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_data() {
         let event_data = EthLockedEvent { locker_address: [0u8; 20], token: "6b175474e89094c44da98b954eedeac495271d0f".to_string(), sender: "00005474e89094c44da98b954eedeac495271d0f".to_string(), amount: 1000, recipient: "123".to_string() };
         let data = event_data.to_log_entry_data();
         let result = EthLockedEvent::from_log_entry_data(&data);
        assert_eq!(result, event_data);
    }
}