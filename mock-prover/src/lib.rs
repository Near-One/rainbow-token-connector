use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Default)]
pub struct MockProver {}

#[near_bindgen]
impl MockProver {
    #[init]
    pub fn new() -> Self { MockProver {} }

    #[result_serializer(borsh)]
    pub fn verify_log_entry(
        &self,
        #[serializer(borsh)] _log_index: u64,
        #[serializer(borsh)] _log_entry_data: Vec<u8>,
        #[serializer(borsh)] _receipt_index: u64,
        #[serializer(borsh)] _receipt_data: Vec<u8>,
        #[serializer(borsh)] _header_data: Vec<u8>,
        #[serializer(borsh)] _proof: Vec<Vec<u8>>,
        #[serializer(borsh)] _skip_bridge_call: bool,
    ) -> bool {
        true
    }
}
