use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{AccountId, Balance, env, ext_contract, Gas, near_bindgen, Promise};
// use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedSet;
use near_sdk::json_types::U128;

use prover::*;

pub mod prover;

type EthAddress = [u8; 20];

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Price per 1 byte of storage from mainnet genesis config.
const STORAGE_PRICE_PER_BYTE: Balance = 100_000_000_000_000_000_000;

const NO_DEPOSIT: Balance = 0;

const BRIDGE_TOKEN_NEW: Gas = 1_000_000_000;

const BRIDGE_TOKEN_INIT_BALANCE: Balance = 30_000_000_000_000_000_000_000_000;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct BridgeTokenFactory {
    /// The account of the prover that we can use to prove
    pub prover_account: AccountId,
    /// Address of the Ethereum locker contract.
    pub locker_address: EthAddress,
    /// Set of created BridgeToken contracts.
    pub tokens: UnorderedSet<String>,
    /// Hashes of the events that were already used.
    pub used_events: UnorderedSet<Vec<u8>>,
}

impl Default for BridgeTokenFactory {
    fn default() -> Self {
        panic!("Fun token should be initialized before usage")
    }
}

#[ext_contract(ext_self)]
pub trait ExtBridgeTokenFactory {
    #[result_serializer(borsh)]
    fn finish_mint(
        &self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: U128,
    ) -> Promise;
}

#[ext_contract(ext_bridge_token)]
pub trait ExtBridgeToken {
    fn mint(&self, account_id: AccountId, amount: U128) -> Promise;

    fn burn(&self, account_id: AccountId, amount: U128) -> Promise;
}

fn validate_eth_address(address: String) -> EthAddress {
    let data =
        hex::decode(address).expect("address should be a valid hex string.");
    assert_eq!(data.len(), 20, "address should be 20 bytes long");
    let mut result  = [0u8; 20];
    result.copy_from_slice(&data);
    result
}

#[near_bindgen]
impl BridgeTokenFactory {
    /// Initializes the contract.
    /// `prover_account`: NEAR account of the Near Prover contract;
    /// `locker_address`: Ethereum address of the locker contract, in hex.
    #[init]
    pub fn new(prover_account: AccountId, locker_address: String) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            prover_account,
            locker_address: validate_eth_address(locker_address),
            tokens: UnorderedSet::new(b"t".to_vec()),
            used_events: UnorderedSet::new(b"u".to_vec()),
        }
    }

    /// Deposit from Ethereum to NEAR based on the proof of the locked tokens.
    /// Must attach enough NEAR funds to cover for storage of the proof.
    /// Also if this is first time this token is used, need to attach extra to deploy the BridgeToken contract.
    #[payable]
    pub fn mint(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        let initial_storage = env::storage_usage();
        self.record_proof(&proof);
        let current_storage = env::storage_usage();
        let attached_deposit = env::attached_deposit();
        let required_deposit =
            Balance::from(current_storage - initial_storage) * STORAGE_PRICE_PER_BYTE;
        let leftover_deposit = attached_deposit - required_deposit;
        let Proof {
            log_index,
            log_entry_data,
            receipt_index,
            receipt_data,
            header_data,
            proof,
        } = proof;
        let event = EthEventData::from_log_entry_data(&log_entry_data);
        assert_eq!(
            event.locker_address,
            self.locker_address,
            "Event's address {} does not match locker address of this token {}",
            hex::encode(&event.locker_address),
            hex::encode(&self.locker_address),
        );
        assert!(
            self.tokens.contains(&event.token), "Bridge token for {} is not deployed yet", event.token
        );
        env::log(format!("{}", event).as_bytes());
        let EthEventData {
            recipient, amount, ..
        } = event;
         ext_prover::verify_log_entry(
             log_index,
             log_entry_data,
             receipt_index,
             receipt_data,
             header_data,
             proof,
             false, // Do not skip bridge call. This is only used for development and diagnostics.
             &self.prover_account,
             0,
             env::prepaid_gas() / 4,
         )
         .then(ext_self::finish_mint(
             recipient,
             amount.into(),
             &env::current_account_id(),
             leftover_deposit,
             env::prepaid_gas() / 2,
         ))
    }

    /// Finish minting once the proof was successfully validated. Can only be called by the contract
    /// itself.
    #[payable]
    pub fn finish_mint(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] address: String,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: U128,
    ) -> Promise {
        let initial_storage = env::storage_usage();
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Finish transfer is only allowed to be called by the contract itself"
        );
        assert!(verification_success, "Failed to verify the proof");

        ext_bridge_token::mint(new_owner_id, amount.into(), &self.get_bridge_token_account_id(address), NO_DEPOSIT, env::prepaid_gas() / 4)
    }

    /// Burn given amount of tokens and unlock it on the Ethereum side for the recipient address.
    /// We return the amount as u128 and the address of the beneficiary as `[u8; 20]` for ease of
    /// processing on Solidity side.
    #[result_serializer(borsh)]
    pub fn burn(&mut self, amount: U128, recipient: String) -> (U128, [u8; 20]) {
        let owner = env::predecessor_account_id();
        let recipient_address = validate_eth_address(recipient);
        // TODO: call token.
        // let mut account = self.get_account(&owner);
        // assert!(account.balance >= amount.0, "Not enough balance");
        // account.balance -= amount.0;
        // self.total_supply -= amount.0;
        // self.set_account(&owner, &account);
        (amount, recipient_address)
    }

    /// Record proof to make sure it is not re-used later for minting.
    fn record_proof(&mut self, proof: &Proof) {
        let mut data = proof.log_index.try_to_vec().unwrap();
        data.extend(proof.receipt_index.try_to_vec().unwrap());
        data.extend(proof.header_data.clone());
        let key = env::sha256(&data);
        assert!(
            !self.used_events.contains(&key),
            "Event cannot be reused for minting."
        );
        self.used_events.insert(&key);
    }

    #[payable]
    pub fn deploy_bridge_token(&mut self, address: String) {
        let _ = validate_eth_address(address.clone());
        assert!(!self.tokens.contains(&address), "BridgeToken contract already exists.");
        let initial_storage = env::storage_usage() as u128;
        self.tokens.insert(&address);
        let current_storage = env::storage_usage() as u128;
        assert!(env::attached_deposit() >= BRIDGE_TOKEN_INIT_BALANCE + STORAGE_PRICE_PER_BYTE * (current_storage - initial_storage), "Not enough attached deposit to complete bridge token creation");
        let bridge_token_account_id = format!("{}.{}", address, env::current_account_id());
        Promise::new(bridge_token_account_id)
            .transfer(BRIDGE_TOKEN_INIT_BALANCE)
            .deploy_contract(include_bytes!("../../res/bridge_token.wasm").to_vec())
            .function_call(b"new".to_vec(), b"{}".to_vec(), NO_DEPOSIT, BRIDGE_TOKEN_NEW);
    }

    pub fn get_bridge_token_account_id(&self, address: String) -> AccountId {
        let _ = validate_eth_address(address.clone());
        assert!(self.tokens.contains(&address), "BridgeToken with such address does not exist.");
        format!("{}.{}", address, env::current_account_id())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use near_sdk::{testing_env, VMContext};
    use near_sdk::MockedBlockchain;

    use super::*;

    fn alice() -> AccountId {
        "alice.near".to_string()
    }
    fn bob() -> AccountId {
        "alice.near".to_string()
    }

    fn prover() -> AccountId {
        "prover".to_string()
    }

    fn token_locker() -> String {
        "6b175474e89094c44da98b954eedeac495271d0f".to_string()
    }

    fn sample_proof() -> Proof {
        Proof {
            log_index: 0,
            log_entry_data: vec![],
            receipt_index: 0,
            receipt_data: vec![],
            header_data: vec![],
            proof: vec![]
        }
    }

    fn get_context(predecessor_account_id: AccountId, attached_deposit: Balance) -> VMContext {
        VMContext {
            current_account_id: prover(),
            signer_account_id: predecessor_account_id.clone(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id,
            input: vec![],
            block_index: 0,
            block_timestamp: 0,
            account_balance: 1_000_000_000_000_000_000_000_000_000u128,
            account_locked_balance: 0,
            storage_usage: 10u64.pow(6),
            attached_deposit,
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view: false,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

    #[test]
    #[should_panic]
    fn test_fail_deploy_bridge_token() {
        testing_env!(get_context(alice(), 0));
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(get_context(alice(), BRIDGE_TOKEN_INIT_BALANCE));
        contract.deploy_bridge_token(token_locker());
    }
    
    #[test]
    #[should_panic]
    fn test_fail_mint_no_token() {
        testing_env!(get_context(alice(), 0));
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(get_context(alice(), STORAGE_PRICE_PER_BYTE * 1000));
        contract.mint(sample_proof());
    }

    #[test]
    fn test_deploy_bridge_token_and_mint() {
        testing_env!(get_context(alice(), 0));
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(get_context(alice(), BRIDGE_TOKEN_INIT_BALANCE * 2));
        contract.deploy_bridge_token(token_locker());
        assert_eq!(contract.get_bridge_token_account_id(token_locker()), format!("{}.{}", token_locker(), prover()));
    }
}