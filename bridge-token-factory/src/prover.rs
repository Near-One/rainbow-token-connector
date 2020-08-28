use std::convert::From;

use borsh::{BorshDeserialize, BorshSerialize};
use eth_types::*;
use ethabi::{Event, EventParam, Hash, ParamType, RawLog, Token, Log};
use ethabi::param_type::Writer;
//use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{ext_contract};

use tiny_keccak::Keccak;

pub type EthAddress = [u8; 20];

pub fn validate_eth_address(address: String) -> EthAddress {
    let data =
        hex::decode(address).expect("address should be a valid hex string.");
    assert_eq!(data.len(), 20, "address should be 20 bytes long");
    let mut result  = [0u8; 20];
    result.copy_from_slice(&data);
    result
}

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

#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct Proof {
    pub log_index: u64,
    pub log_entry_data: Vec<u8>,
    pub receipt_index: u64,
    pub receipt_data: Vec<u8>,
    pub header_data: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

pub type EthEventParams = Vec<(String, ParamType, bool)>;

pub struct EthEvent {
    pub locker_address: EthAddress,
    pub log: Log,
}

impl EthEvent {
    pub fn from_log_entry_data(name: &str, params: EthEventParams, data: &[u8]) -> Self {
        let event = Event { name: name.to_string(), inputs: params.into_iter().map(|(name, kind, indexed)| EventParam { name, kind, indexed }).collect(), anonymous: false };
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
        Self {
            locker_address,
            log
        }
    }

    pub fn to_log_entry_data(name: &str, params: EthEventParams, locker_address: EthAddress, indexes: Vec<Vec<u8>>, values: Vec<Token>) -> Vec<u8> {
        let event = Event { name: name.to_string(), inputs: params.into_iter().map(|(name, kind, indexed)| EventParam { name: name.to_string(), kind, indexed }).collect(), anonymous: false };
        let params: Vec<ParamType> = event.inputs.iter().map(|p| p.kind.clone()).collect();
        let topics = indexes.into_iter().map(|value| H256::from(value)).collect();
        let log_entry = LogEntry {
            address: locker_address.into(),
            topics: vec![vec![
                long_signature(&event.name, &params).0.into()], topics].concat(),
            data: ethabi::encode(&values),
        };
        rlp::encode(&log_entry)
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
