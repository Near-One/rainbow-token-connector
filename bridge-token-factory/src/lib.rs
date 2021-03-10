use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedSet;
use near_sdk::json_types::U128;
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Balance, Gas, Promise, PromiseResult, PublicKey,
};

use admin_controlled::{AdminControlled, Mask};
use near_lib::token::ext_nep21;

pub use lock_event::EthLockedEvent;
use prover::*;
pub use prover::{validate_eth_address, Proof};
pub use unlock_event::EthUnlockedEvent;

mod lock_event;
pub mod prover;
mod unlock_event;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Price per 1 byte of storage from mainnet genesis config.
const STORAGE_PRICE_PER_BYTE: Balance = 100_000_000_000_000_000_000; // 1e20yN, 0.0001N

const NO_DEPOSIT: Balance = 0;

/// Gas to initialize BridgeToken contract.
const BRIDGE_TOKEN_NEW: Gas = 10_000_000_000_000;

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = 30_000_000_000_000_000_000_000_000; // 3e25yN, 30N

const TRANSFER_FROM_GAS: Gas = 10_000_000_000_000;

const TRANSFER_GAS: Gas = 10_000_000_000_000;

#[derive(Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum ResultType {
    Withdraw,
    Lock,
}
const UNPAUSE_ALL: Mask = 0;
const PAUSE_DEPLOY_TOKEN: Mask = 1 << 0;
const PAUSE_DEPOSIT: Mask = 1 << 1;
const PAUSE_WITHDRAW: Mask = 1 << 2;
const PAUSE_LOCK: Mask = 1 << 3;
const PAUSE_UNLOCK: Mask = 1 << 4;

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
    /// Public key of the account deploying the factory.
    pub owner_pk: PublicKey,
    /// Mask determining all paused functions
    paused: Mask,
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
        #[serializer(borsh)] proof: Proof,
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
        #[serializer(borsh)] proof: Proof,
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
            owner_pk: env::signer_account_pk(),
            paused: Mask::default(),
        }
    }

    /// Deposit from Ethereum to NEAR based on the proof of the locked tokens.
    /// Must attach enough NEAR funds to cover for storage of the proof.
    /// Also if this is first time this token is used, need to attach extra to deploy the BridgeToken contract.
    #[payable]
    pub fn deposit(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        self.check_not_paused(PAUSE_DEPOSIT);
        let event = EthLockedEvent::from_log_entry_data(&proof.log_entry_data);
        assert_eq!(
            event.locker_address,
            self.locker_address,
            "Event's address {} does not match locker address of this token {}",
            hex::encode(&event.locker_address),
            hex::encode(&self.locker_address),
        );
        assert!(
            self.tokens.contains(&event.token),
            "Bridge token for {} is not deployed yet",
            event.token
        );
        let proof_1 = proof.clone();
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
        )
        .then(ext_self::finish_deposit(
            event.token,
            event.recipient,
            event.amount,
            proof_1,
            &env::current_account_id(),
            env::attached_deposit(),
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
        #[serializer(borsh)] proof: Proof,
    ) -> Promise {
        assert_self();
        assert!(verification_success, "Failed to verify the proof");
        self.record_proof(&proof);

        ext_bridge_token::mint(
            new_owner_id,
            amount.into(),
            &self.get_bridge_token_account_id(token),
            NO_DEPOSIT,
            env::prepaid_gas() / 2,
        )
    }

    /// Burn given amount of tokens and unlock it on the Ethereum side for the recipient address.
    /// We return the amount as u128 and the address of the beneficiary as `[u8; 20]` for ease of
    /// processing on Solidity side.
    /// Caller must be <token_address>.<current_account_id>, where <token_address> exists in the `tokens`.
    #[result_serializer(borsh)]
    pub fn finish_withdraw(
        &mut self,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: String,
    ) -> (ResultType, u128, [u8; 20], [u8; 20]) {
        self.check_not_paused(PAUSE_WITHDRAW);
        let token = env::predecessor_account_id();
        let parts: Vec<&str> = token.split(".").collect();
        assert_eq!(
            token,
            format!("{}.{}", parts[0], env::current_account_id()),
            "Only sub accounts of BridgeTokenFactory can call this method."
        );
        assert!(
            self.tokens.contains(&parts[0].to_string()),
            "Such BridgeToken does not exist."
        );
        let token_address = validate_eth_address(parts[0].to_string());
        let recipient_address = validate_eth_address(recipient);
        (
            ResultType::Withdraw,
            amount.into(),
            token_address,
            recipient_address,
        )
    }

    #[payable]
    pub fn deploy_bridge_token(&mut self, address: String) -> Promise {
        self.check_not_paused(PAUSE_DEPLOY_TOKEN);
        let address = address.to_lowercase();
        let _ = validate_eth_address(address.clone());
        assert!(
            !self.tokens.contains(&address),
            "BridgeToken contract already exists."
        );
        let initial_storage = env::storage_usage() as u128;
        self.tokens.insert(&address);
        let current_storage = env::storage_usage() as u128;
        assert!(
            env::attached_deposit()
                >= BRIDGE_TOKEN_INIT_BALANCE
                    + STORAGE_PRICE_PER_BYTE * (current_storage - initial_storage),
            "Not enough attached deposit to complete bridge token creation"
        );
        let bridge_token_account_id = format!("{}.{}", address, env::current_account_id());
        Promise::new(bridge_token_account_id)
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE)
            .add_full_access_key(self.owner_pk.clone())
            .deploy_contract(include_bytes!("../../res/bridge_token.wasm").to_vec())
            .function_call(
                b"new".to_vec(),
                b"{}".to_vec(),
                NO_DEPOSIT,
                BRIDGE_TOKEN_NEW,
            )
    }

    pub fn get_bridge_token_account_id(&self, address: String) -> AccountId {
        let address = address.to_lowercase();
        let _ = validate_eth_address(address.clone());
        assert!(
            self.tokens.contains(&address),
            "BridgeToken with such address does not exist."
        );
        format!("{}.{}", address, env::current_account_id())
    }

    /// Locks NEP-21 token on NEAR side to mint on Ethereum it's counterpart.
    #[payable]
    pub fn lock(&mut self, token: AccountId, amount: U128, recipient: String) -> Promise {
        self.check_not_paused(PAUSE_LOCK);
        assert!(false, "Native NEP21 on Ethereum is disabled.");
        let address = validate_eth_address(recipient);
        ext_nep21::transfer_from(
            env::predecessor_account_id(),
            env::current_account_id(),
            amount,
            &token,
            env::attached_deposit(),
            TRANSFER_FROM_GAS,
        )
        .then(ext_self::finish_lock(
            amount.into(),
            address,
            token,
            &env::current_account_id(),
            NO_DEPOSIT,
            env::prepaid_gas() / 3,
        ))
    }

    /// Callback after transfer_from happened.
    #[result_serializer(borsh)]
    pub fn finish_lock(
        &self,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: [u8; 20],
        #[serializer(borsh)] token: String,
    ) -> (ResultType, String, u128, [u8; 20]) {
        assert!(false, "Native NEP21 on Ethereum is disabled.");
        assert_self();
        assert!(is_promise_success());
        (ResultType::Lock, token, amount.into(), recipient)
    }

    #[payable]
    pub fn unlock(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        self.check_not_paused(PAUSE_UNLOCK);
        assert!(false, "Native NEP21 on Ethereum is disabled.");
        let event = EthUnlockedEvent::from_log_entry_data(&proof.log_entry_data);
        assert_eq!(
            event.locker_address,
            self.locker_address,
            "Event's address {} does not match locker address of this token {}",
            hex::encode(&event.locker_address),
            hex::encode(&self.locker_address),
        );
        let proof_1 = proof.clone();
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
        )
        .then(ext_self::finish_unlock(
            event.token,
            event.recipient,
            event.amount,
            proof_1,
            &env::current_account_id(),
            env::attached_deposit(),
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
        #[serializer(borsh)] proof: Proof,
    ) -> Promise {
        assert!(false, "Native NEP21 on Ethereum is disabled.");
        assert_self();
        assert!(verification_success, "Failed to verify the proof");
        self.record_proof(&proof);
        ext_nep21::transfer(
            recipient,
            amount.into(),
            &token,
            env::attached_deposit(),
            TRANSFER_GAS,
        )
    }

    /// Record proof to make sure it is not re-used later for anther deposit.
    fn record_proof(&mut self, proof: &Proof) -> Balance {
        // TODO: Instead of sending the full proof (clone only relevant parts of the Proof)
        //       log_index / receipt_index / header_data
        assert_self();
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

impl AdminControlled for BridgeTokenFactory {
    fn get_paused(&self) -> Mask {
        self.paused
    }

    fn set_paused(&mut self, paused: Mask) {
        self.assert_owner();
        self.paused = paused;
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use near_sdk::testing_env;
    use near_sdk::MockedBlockchain;
    use near_test::context::VMContextBuilder;

    use super::*;
    use near_sdk::env::sha256;
    use std::convert::TryInto;
    use std::panic;
    use uint::rustc_hex::{FromHex, ToHex};

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

    /// Generate a valid ethereum address
    fn ethereum_address_from_id(id: u8) -> String {
        let mut buffer = vec![id];
        sha256(buffer.as_mut())
            .into_iter()
            .take(20)
            .collect::<Vec<_>>()
            .to_hex()
    }

    fn sample_proof() -> Proof {
        Proof {
            log_index: 0,
            log_entry_data: vec![],
            receipt_index: 0,
            receipt_data: vec![],
            header_data: vec![],
            proof: vec![],
        }
    }

    fn create_proof(locker: String, token: String) -> Proof {
        let event_data = EthLockedEvent {
            locker_address: locker
                .from_hex::<Vec<_>>()
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),

            token,
            sender: "00005474e89094c44da98b954eedeac495271d0f".to_string(),
            amount: 1000,
            recipient: "123".to_string(),
        };

        Proof {
            log_index: 0,
            log_entry_data: event_data.to_log_entry_data(),
            receipt_index: 0,
            receipt_data: vec![],
            header_data: vec![],
            proof: vec![],
        }
    }

    #[test]
    #[should_panic]
    fn test_fail_deploy_bridge_token() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE)
            .finish());
        contract.deploy_bridge_token(token_locker());
    }

    #[test]
    #[should_panic]
    fn test_fail_deposit_no_token() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .attached_deposit(STORAGE_PRICE_PER_BYTE * 1000)
            .finish());
        contract.deposit(sample_proof());
    }

    #[test]
    fn test_deploy_bridge_token() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .predecessor_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.deploy_bridge_token(token_locker());
        assert_eq!(
            contract.get_bridge_token_account_id(token_locker()),
            format!("{}.{}", token_locker(), bridge_token_factory())
        );

        let uppercase_address = "0f5Ea0A652E851678Ebf77B69484bFcD31F9459B".to_string();
        contract.deploy_bridge_token(uppercase_address.clone());
        assert_eq!(
            contract.get_bridge_token_account_id(uppercase_address.clone()),
            format!(
                "{}.{}",
                uppercase_address.to_lowercase(),
                bridge_token_factory()
            )
        );
    }

    #[test]
    fn test_finish_withdraw() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.deploy_bridge_token(token_locker());
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .predecessor_account_id(format!("{}.{}", token_locker(), bridge_token_factory()))
            .finish());
        let address = validate_eth_address(token_locker());
        assert_eq!(
            contract.finish_withdraw(1_000, token_locker()),
            (ResultType::Withdraw, 1_000, address, address)
        );
    }

    #[test]
    fn deploy_bridge_token_paused() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());

        // User alice can deploy a new bridge token
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .predecessor_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.deploy_bridge_token(ethereum_address_from_id(0));

        // Admin pause deployment of new token
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.set_paused(PAUSE_DEPLOY_TOKEN);

        // Admin can still deploy new tokens after paused
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.deploy_bridge_token(ethereum_address_from_id(1));

        // User alice can't deploy a new bridge token when it is paused
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        panic::catch_unwind(move || {
            contract.deploy_bridge_token(ethereum_address_from_id(2));
        })
        .unwrap_err();
    }

    #[test]
    fn only_admin_can_pause() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        // Admin can pause
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .finish());
        contract.set_paused(0b1111);

        // Alice can't pause
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .finish());

        panic::catch_unwind(move || {
            contract.set_paused(0);
        })
        .unwrap_err();
    }

    #[test]
    fn deposit_paused() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        contract.deposit(create_proof(token_locker(), erc20_address.clone()));

        // Pause deposit
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.set_paused(PAUSE_DEPOSIT);

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());

        // Check it is NOT possible to use deposit while the contract is paused
        panic::catch_unwind(move || {
            contract.deposit(create_proof(token_locker(), erc20_address.clone()));
        })
        .unwrap_err();
        
        // Unpause everything
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.set_paused(UNPAUSE_ALL);

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
            
        // Check it is possible to use deposit again after the contract is unpaused
        contract.deposit(create_proof(token_locker(), erc20_address));
    }

    #[test]
    fn withdraw_paused() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());

        let erc20_address = ethereum_address_from_id(0);
        let token_name = format!("{}.{}", erc20_address, bridge_token_factory());
        contract.deploy_bridge_token(erc20_address.clone());

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .predecessor_account_id(token_name.clone())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());

        // Check it is possible to use withdraw while the contract is NOT paused
        let recipient = ethereum_address_from_id(1);
        contract.finish_withdraw(0, recipient.clone());

        // Pause withdraw
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.set_paused(PAUSE_WITHDRAW);

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .predecessor_account_id(token_name.clone())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());

        // Check it is NOT possible to use withdraw while the contract is paused
        panic::catch_unwind(move || {
            contract.finish_withdraw(0, recipient.clone());
        })
        .unwrap_err();
        
        // Unpause everything
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.set_paused(UNPAUSE_ALL);

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
            
        // Check it is possible to use withdraw again after the contract is unpaused
        contract.finish_withdraw(0, recipient);
    }

    /// Check after all is paused deposit is not available
    #[test]
    fn all_paused() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        contract.deposit(create_proof(token_locker(), erc20_address.clone()));

        // Pause everything
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        contract.set_paused(
            PAUSE_DEPLOY_TOKEN | PAUSE_DEPOSIT | PAUSE_WITHDRAW | PAUSE_LOCK | PAUSE_UNLOCK,
        );

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());

        // Check it is NOT possible to use deposit while the contract is paused
        panic::catch_unwind(move || {
            contract.deposit(create_proof(token_locker(), erc20_address));
        })
        .unwrap_err();
    }

    /// Check after all is paused and unpaused deposit works
    #[test]
    fn no_paused() {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(alice())
            .finish());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        contract.deposit(create_proof(token_locker(), erc20_address.clone()));

        // Pause everything
        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(bridge_token_factory())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());

        contract.set_paused(
            PAUSE_DEPLOY_TOKEN | PAUSE_DEPOSIT | PAUSE_WITHDRAW | PAUSE_LOCK | PAUSE_UNLOCK,
        );
        contract.set_paused(UNPAUSE_ALL);

        testing_env!(VMContextBuilder::new()
            .current_account_id(bridge_token_factory())
            .signer_account_id(alice())
            .attached_deposit(BRIDGE_TOKEN_INIT_BALANCE * 2)
            .finish());

        // Check the deposit works after pausing and unpausing everything
        contract.deposit(create_proof(token_locker(), erc20_address));
    }
}
