use crate::*;

pub type Mask = u128;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct OldState {
    pub prover_account: AccountId,
    pub locker_address: EthAddress,
    pub tokens: UnorderedSet<String>,
    pub used_events: UnorderedSet<Vec<u8>>,
    pub owner_pk: PublicKey,
    pub bridge_token_storage_deposit_required: Balance,
    pub paused: Mask,
}

#[near_bindgen]
impl BridgeTokenFactory {
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        // retrieve the current state from the contract
        let old_state: OldState = env::state_read().expect("failed");

        // return the new state
        Self {
            prover_account: old_state.prover_account,
            locker_address: old_state.locker_address,
            tokens: old_state.tokens,
            used_events: old_state.used_events,
            owner_pk: old_state.owner_pk,
            bridge_token_storage_deposit_required: old_state.bridge_token_storage_deposit_required,
            deposit_fee: UnorderedMap::new(StorageKey::DepositFee),
            withdraw_fee: UnorderedMap::new(StorageKey::WihdrawFee),
            withdraw_fee_per_silo: UnorderedMap::new(StorageKey::WithdrawFeePerSilo),
            deposit_fee_per_silo: UnorderedMap::new(StorageKey::DespositFeePerSilo),
        }
    }
}
