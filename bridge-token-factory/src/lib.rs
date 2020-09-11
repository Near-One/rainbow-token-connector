use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{AccountId, Balance, env, ext_contract, Gas, near_bindgen, Promise, PromiseResult};
// use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedSet;
use near_sdk::json_types::U128;

use near_lib::token::ext_nep21;

use prover::*;
pub use prover::{validate_eth_address, Proof};
pub use lock_event::EthLockedEvent;
pub use unlock_event::EthUnlockedEvent;

pub mod prover;
mod lock_event;
mod unlock_event;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Price per 1 byte of storage from mainnet genesis config.
const STORAGE_PRICE_PER_BYTE: Balance = 100_000_000_000_000_000_000;

const NO_DEPOSIT: Balance = 0;

/// Gas to initialize BridgeToken contract.
const BRIDGE_TOKEN_NEW: Gas = 10_000_000_000_000;

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = 30_000_000_000_000_000_000_000_000;

const TRANSFER_FROM_GAS: Gas = 10_000_000_000_000;

const TRANSFER_GAS: Gas = 10_000_000_000_000;

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
    fn finish_deposit(
        &self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: Balance,
    ) -> Promise;

    #[result_serializer(borsh)]
    fn finish_lock(
        &self,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: [u8; 20],
        #[serializer(borsh)] token: String,
    ) -> (U128, [u8; 20], String);

    #[result_serializer(borsh)]
    fn finish_unlock(
        &self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: AccountId,
        #[serializer(borsh)] recipient: AccountId,
        #[serializer(borsh)] amount: Balance,
    ) -> Promise;
}

#[ext_contract(ext_bridge_token)]
pub trait ExtBridgeToken {
    fn mint(&self, account_id: AccountId, amount: U128) -> Promise;
}

pub fn assert_self() {
    assert_eq!(env::predecessor_account_id(), env::current_account_id());
}

pub fn is_promise_success() -> bool {
    assert_eq!(
        env::promise_results_count(),
        1,
        "Contract expected a result on the callback"
    );
    match env::promise_result(0) {
        PromiseResult::Successful(_) => true,
        _ => false,
    }
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
    pub fn deposit(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        let leftover_deposit = self.record_proof(&proof);
        let event = EthLockedEvent::from_log_entry_data(&proof.log_entry_data);
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
        ext_prover::verify_log_entry(
            proof.log_index,
            proof.log_entry_data,
            proof.receipt_index,
            proof.receipt_data,
            proof.header_data,
            proof.proof,
            false, // Do not skip bridge call. This is only used for development and diagnostics.
            &self.prover_account,
            NO_DEPOSIT,
            env::prepaid_gas() / 4,
        ).then(ext_self::finish_deposit(
             event.token,
             event.recipient,
             event.amount,
             &env::current_account_id(),
             leftover_deposit,
             env::prepaid_gas() / 2,
         ))
    }

    /// Finish depositing once the proof was successfully validated. Can only be called by the contract
    /// itself.
    #[payable]
    pub fn finish_deposit(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: Balance,
    ) -> Promise {
        assert_self();
        assert!(verification_success, "Failed to verify the proof");

        ext_bridge_token::mint(new_owner_id, amount.into(), &self.get_bridge_token_account_id(token), NO_DEPOSIT, env::prepaid_gas() / 2)
    }

    /// Burn given amount of tokens and unlock it on the Ethereum side for the recipient address.
    /// We return the amount as u128 and the address of the beneficiary as `[u8; 20]` for ease of
    /// processing on Solidity side.
    /// Caller must be <token_address>.<current_account_id>, where <token_address> exists in the `tokens`.
    #[result_serializer(borsh)]
    pub fn finish_withdraw(
        &mut self,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: String
    ) -> (u128, [u8; 20], [u8; 20]) {
        let token = env::predecessor_account_id();
        let parts: Vec<&str> = token.split(".").collect();
        assert_eq!(token, format!("{}.{}", parts[0], env::current_account_id()), "Only sub accounts of BridgeTokenFactory can call this method.");
        assert!(self.tokens.contains(&parts[0].to_string()), "Such BridgeToken does not exist.");
        let token_address = validate_eth_address(parts[0].to_string());
        let recipient_address = validate_eth_address(recipient);
        (amount.into(), token_address, recipient_address)
    }

    #[payable]
    pub fn deploy_bridge_token(&mut self, address: String) -> Promise {
        let address = address.to_lowercase();
        let _ = validate_eth_address(address.clone());
        assert!(!self.tokens.contains(&address), "BridgeToken contract already exists.");
        let initial_storage = env::storage_usage() as u128;
        self.tokens.insert(&address);
        let current_storage = env::storage_usage() as u128;
        assert!(env::attached_deposit() >= BRIDGE_TOKEN_INIT_BALANCE + STORAGE_PRICE_PER_BYTE * (current_storage - initial_storage), "Not enough attached deposit to complete bridge token creation");
        let bridge_token_account_id = format!("{}.{}", address, env::current_account_id());
        Promise::new(bridge_token_account_id)
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE)
            .deploy_contract(include_bytes!("../../res/bridge_token.wasm").to_vec())
            .function_call(b"new".to_vec(), b"{}".to_vec(), NO_DEPOSIT, BRIDGE_TOKEN_NEW)
    }

    pub fn get_bridge_token_account_id(&self, address: String) -> AccountId {
        let address = address.to_lowercase();
        let _ = validate_eth_address(address.clone());
        assert!(self.tokens.contains(&address), "BridgeToken with such address does not exist.");
        format!("{}.{}", address, env::current_account_id())
    }

    /// Locks NEP-21 token on NEAR side to mint on Ethereum it's counterpart.
    #[payable]
    pub fn lock(&mut self, token: AccountId, amount: U128, recipient: String) -> Promise {
        let address = validate_eth_address(recipient);
        ext_nep21::transfer_from(env::predecessor_account_id(), env::current_account_id(), amount, &token, env::attached_deposit(), TRANSFER_FROM_GAS)
            .then(ext_self::finish_lock(amount.into(), address, token, &env::current_account_id(), NO_DEPOSIT, env::prepaid_gas() / 3))
    }

    /// Callback after transfer_from happened.
    #[result_serializer(borsh)]
    pub fn finish_lock(
        &self,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: [u8; 20],
        #[serializer(borsh)] token: String) -> (String, u128, [u8; 20]) {
        assert_self();
        assert!(is_promise_success());
        (token, amount.into(), recipient)
    }

    #[payable]
    pub fn unlock(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        let leftover_deposit = self.record_proof(&proof);
        let event = EthUnlockedEvent::from_log_entry_data(&proof.log_entry_data);
        assert_eq!(
            event.locker_address,
            self.locker_address,
            "Event's address {} does not match locker address of this token {}",
            hex::encode(&event.locker_address),
            hex::encode(&self.locker_address),
        );
        ext_prover::verify_log_entry(
            proof.log_index,
            proof.log_entry_data,
            proof.receipt_index,
            proof.receipt_data,
            proof.header_data,
            proof.proof,
            false, // Do not skip bridge call. This is only used for development and diagnostics.
            &self.prover_account,
            NO_DEPOSIT,
            env::prepaid_gas() / 4,
        ).then(ext_self::finish_unlock(
            event.token,
            event.recipient,
            event.amount,
            &env::current_account_id(),
            leftover_deposit,
            env::prepaid_gas() / 2,
        ))
    }

    #[payable]
    pub fn finish_unlock(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: AccountId,
        #[serializer(borsh)] recipient: AccountId,
        #[serializer(borsh)] amount: Balance,
    ) -> Promise {
        assert_self();
        assert!(verification_success, "Failed to verify the proof");
        ext_nep21::transfer(recipient, amount.into(), &token, env::attached_deposit(), TRANSFER_GAS)
    }

    /// Record proof to make sure it is not re-used later for anther deposit.
    fn record_proof(&mut self, proof: &Proof) -> Balance {
        let initial_storage = env::storage_usage();
        let mut data = proof.log_index.try_to_vec().unwrap();
        data.extend(proof.receipt_index.try_to_vec().unwrap());
        data.extend(proof.header_data.clone());
        let key = env::sha256(&data);
        assert!(
            !self.used_events.contains(&key),
            "Event cannot be reused for depositing."
        );
        self.used_events.insert(&key);
        let current_storage = env::storage_usage();
        let attached_deposit = env::attached_deposit();
        let required_deposit =
            Balance::from(current_storage - initial_storage) * STORAGE_PRICE_PER_BYTE;
        attached_deposit - required_deposit
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use near_sdk::testing_env;
    use near_sdk::MockedBlockchain;
    use near_test::context::VMContextBuilder;

    use super::*;

    fn alice() -> AccountId {
        "alice.near".to_string()
    }

    fn prover() -> AccountId {
        "prover".to_string()
    }

    fn bridge_token_factory() -> AccountId {
        "bridge".to_string()
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

    #[test]
    #[should_panic]
    fn test_fail_deploy_bridge_token() {
        testing_env!(VMContextBuilder::new().predecessor_account_id(alice()).finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new().predecessor_account_id(alice()).attached_deposit(BRIDGE_TOKEN_INIT_BALANCE).finish());
        contract.deploy_bridge_token(token_locker());
    }
    
    #[test]
    #[should_panic]
    fn test_fail_deposit_no_token() {
        testing_env!(VMContextBuilder::new().predecessor_account_id(alice()).finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new().predecessor_account_id(alice()).attached_deposit(STORAGE_PRICE_PER_BYTE * 1000).finish());
        contract.deposit(sample_proof());
    }

    #[test]
    fn test_deploy_bridge_token_and_deposit() {
        testing_env!(VMContextBuilder::new().predecessor_account_id(alice()).finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new().current_account_id(bridge_token_factory()).predecessor_account_id(alice()).attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2).finish());
        contract.deploy_bridge_token(token_locker());
        assert_eq!(contract.get_bridge_token_account_id(token_locker()), format!("{}.{}", token_locker(), bridge_token_factory()));

        let uppercase_address = "0f5Ea0A652E851678Ebf77B69484bFcD31F9459B".to_string();
        contract.deploy_bridge_token(uppercase_address.clone());
        assert_eq!(contract.get_bridge_token_account_id(uppercase_address.clone()), format!("{}.{}", uppercase_address.to_lowercase(), bridge_token_factory()));
    }

    #[test]
    fn test_finish_withdraw() {
        testing_env!(VMContextBuilder::new().predecessor_account_id(alice()).finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new().predecessor_account_id(alice()).attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2).finish());
        contract.deploy_bridge_token(token_locker());
        testing_env!(VMContextBuilder::new().current_account_id(bridge_token_factory()).predecessor_account_id(format!("{}.{}", token_locker(), bridge_token_factory())).finish());
        let address = validate_eth_address(token_locker());
        assert_eq!(contract.finish_withdraw(1_000, token_locker()), (1_000,  address, address));
    }    
}