use std::convert::TryInto;

use admin_controlled::{AdminControlled, Mask};
use near_sdk::{
    AccountId, Balance, env, ext_contract, Gas, near_bindgen, PanicOnDefault, Promise, PublicKey,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{UnorderedMap, UnorderedSet};
use near_sdk::json_types::{Base64VecU8, U128, ValidAccountId};

use bridge_common::{FT_TRANSFER_CALL_GAS, NO_DEPOSIT, parse_recipient, Recipient, ResultType, VERIFY_LOG_ENTRY_GAS};
use bridge_common::prover::*;
pub use bridge_common::prover::{Proof, validate_eth_address};
pub use lock_event::EthLockedEvent;
pub use log_metadata_event::TokenMetadataEvent;

mod lock_event;
mod log_metadata_event;

near_sdk::setup_alloc!();

const BRIDGE_TOKEN_BINARY: &'static [u8] = include_bytes!(std::env!(
    "BRIDGE_TOKEN",
    "Set BRIDGE_TOKEN to be the path of the bridge token binary"
));

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = 3_000_000_000_000_000_000_000_000; // 3e24yN, 3N

/// Gas to initialize BridgeToken contract.
const BRIDGE_TOKEN_NEW: Gas = 10_000_000_000_000;

/// Gas to call mint method on bridge token.
const MINT_GAS: Gas = 10_000_000_000_000;

/// Gas to call finish deposit method.
/// This doesn't cover the gas required for calling mint method.
const FINISH_DEPOSIT_GAS: Gas = 30_000_000_000_000;

/// Gas to call finish update_metadata method.
const FINISH_UPDATE_METADATA_GAS: Gas = 5_000_000_000_000;

/// Amount of gas used by set_metadata in the factory, without taking into account
/// the gas consumed by the promise.
const OUTER_SET_METADATA_GAS: Gas = 15_000_000_000_000;

/// Amount of gas used by bridge token to set the metadata.
const SET_METADATA_GAS: Gas = 5_000_000_000_000;

/// Controller storage key.
const CONTROLLER_STORAGE_KEY: &[u8] = b"aCONTROLLER";

/// Metadata connector address storage key.
const METADATA_CONNECTOR_ETH_ADDRESS_STORAGE_KEY: &[u8] = b"aM_CONNECTOR";

/// Prefix used to store a map between tokens and timestamp `t`, where `t` stands for the
/// block on Ethereum where the metadata for given token was emitted.
/// The prefix is made specially short since it becomes more expensive with larger prefixes.
const TOKEN_TIMESTAMP_MAP_PREFIX: &[u8] = b"aTT";

const PAUSE_DEPLOY_TOKEN: Mask = 1 << 0;
const PAUSE_DEPOSIT: Mask = 1 << 1;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
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
    /// Balance required to register a new account in the BridgeToken
    pub bridge_token_storage_deposit_required: Balance,
    /// Mask determining all paused functions
    paused: Mask,
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
    fn finish_updating_metadata(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] name: String,
        #[serializer(borsh)] symbol: String,
        #[serializer(borsh)] decimals: u8,
        #[serializer(borsh)] timestamp: u64,
    ) -> Promise;
}

#[ext_contract(ext_fungible_token)]
pub trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[ext_contract(ext_bridge_token)]
pub trait ExtBridgeToken {
    fn mint(&self, account_id: AccountId, amount: U128);

    fn ft_transfer_call(
        &mut self,
        receiver_id: ValidAccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128>;

    fn set_metadata(
        &mut self,
        name: Option<String>,
        symbol: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
        decimals: Option<u8>,
        icon: Option<String>,
    );
}

pub fn assert_self() {
    assert_eq!(env::predecessor_account_id(), env::current_account_id());
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
            bridge_token_storage_deposit_required:
                near_contract_standards::fungible_token::FungibleToken::new(b"t".to_vec())
                    .account_storage_usage as Balance
                    * env::storage_byte_cost(),
            paused: Mask::default(),
        }
    }

    pub fn update_metadata(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        let event = TokenMetadataEvent::from_log_entry_data(&proof.log_entry_data);

        let expected_metadata_connector = self.metadata_connector();

        assert_eq!(
            Some(hex::encode(event.metadata_connector)),
            expected_metadata_connector,
            "Event's address {} does not match contract address of this token {:?}",
            hex::encode(&event.metadata_connector),
            expected_metadata_connector,
        );

        assert!(
            self.tokens.contains(&event.token),
            "Bridge token for {} is not deployed yet",
            event.token
        );

        let last_timestamp = self
            .token_metadata_last_update()
            .get(&event.token)
            .unwrap_or_default();

        // Note that it is allowed for event.timestamp to be equal to last_timestamp.
        // This disallow replacing the metadata with old information, but allows replacing with information
        // from the same block. This is useful in case there is a failure in the cross-contract to the
        // bridge token with storage but timestamp in this contract is updated. In those cases the call
        // can be made again, to make the replacement effective.
        assert!(event.timestamp >= last_timestamp);

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
            VERIFY_LOG_ENTRY_GAS,
        )
        .then(ext_self::finish_updating_metadata(
            event.token,
            event.name,
            event.symbol,
            event.decimals,
            event.timestamp,
            &env::current_account_id(),
            env::attached_deposit(),
            FINISH_UPDATE_METADATA_GAS + SET_METADATA_GAS,
        ))
    }
    /// Deposit from Ethereum to NEAR based on the proof of the locked tokens.
    /// Must attach enough NEAR funds to cover for storage of the proof.
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
            VERIFY_LOG_ENTRY_GAS,
        )
        .then(ext_self::finish_deposit(
            event.token,
            event.recipient,
            event.amount,
            proof_1,
            &env::current_account_id(),
            env::attached_deposit(),
            FINISH_DEPOSIT_GAS + MINT_GAS + FT_TRANSFER_CALL_GAS,
        ))
    }

    /// Return all registered tokens
    pub fn get_tokens(&self) -> Vec<String> {
        self.tokens.iter().collect::<Vec<_>>()
    }

    fn set_token_metadata_timestamp(&mut self, token: &String, timestamp: u64) -> Balance {
        let initial_storage = env::storage_usage();
        self.token_metadata_last_update().insert(&token, &timestamp);
        let current_storage = env::storage_usage();
        let required_deposit =
            Balance::from(current_storage - initial_storage) * env::storage_byte_cost();
        required_deposit
    }

    /// Finish updating token metadata once the proof was successfully validated.
    /// Can only be called by the contract itself.
    pub fn finish_updating_metadata(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] name: String,
        #[serializer(borsh)] symbol: String,
        #[serializer(borsh)] decimals: u8,
        #[serializer(borsh)] timestamp: u64,
    ) {
        assert_self();
        assert!(verification_success, "Failed to verify the proof");

        let required_deposit = self.set_token_metadata_timestamp(&token, timestamp);

        assert!(env::attached_deposit() >= required_deposit);

        env::log(
            format!(
                "Finish updating metadata. Name: {} Symbol: {:?} Decimals: {:?} at: {:?}",
                name, symbol, decimals, timestamp
            )
            .as_bytes(),
        );

        let reference = None;
        let reference_hash = None;
        let icon = None;

        ext_bridge_token::set_metadata(
            name.into(),
            symbol.into(),
            reference,
            reference_hash,
            decimals.into(),
            icon,
            &self.get_bridge_token_account_id(token.clone()),
            env::attached_deposit() - required_deposit,
            SET_METADATA_GAS,
        );
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
        #[serializer(borsh)] new_owner_id: String,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] proof: Proof,
    ) -> Promise {
        assert_self();
        assert!(verification_success, "Failed to verify the proof");

        let required_deposit = self.record_proof(&proof);

        assert!(
            env::attached_deposit()
                >= required_deposit + self.bridge_token_storage_deposit_required
        );

        let Recipient { target, message } = parse_recipient(new_owner_id);

        env::log(format!("Finish deposit. Target:{} Message:{:?}", target, message).as_bytes());

        match message {
            Some(message) => ext_bridge_token::mint(
                env::current_account_id(),
                amount.into(),
                &self.get_bridge_token_account_id(token.clone()),
                env::attached_deposit() - required_deposit,
                MINT_GAS,
            )
            .then(ext_bridge_token::ft_transfer_call(
                target.try_into().unwrap(),
                amount.into(),
                None,
                message,
                &self.get_bridge_token_account_id(token),
                1,
                FT_TRANSFER_CALL_GAS,
            )),
            None => ext_bridge_token::mint(
                target,
                amount.into(),
                &self.get_bridge_token_account_id(token),
                env::attached_deposit() - required_deposit,
                MINT_GAS,
            ),
        }
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
    ) -> ResultType {
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
        ResultType::Withdraw {
            amount: amount.into(),
            token: token_address,
            recipient: recipient_address,
        }
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
                    + env::storage_byte_cost() * (current_storage - initial_storage),
            "Not enough attached deposit to complete bridge token creation"
        );
        let bridge_token_account_id = format!("{}.{}", address, env::current_account_id());
        Promise::new(bridge_token_account_id)
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE)
            .add_full_access_key(self.owner_pk.clone())
            .deploy_contract(BRIDGE_TOKEN_BINARY.to_vec())
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

    /// Checks whether the provided proof is already used
    pub fn is_used_proof(&self, #[serializer(borsh)] proof: Proof) -> bool {
        self.used_events.contains(&proof.get_key())
    }

    /// Record proof to make sure it is not re-used later for anther deposit.
    fn record_proof(&mut self, proof: &Proof) -> Balance {
        // TODO: Instead of sending the full proof (clone only relevant parts of the Proof)
        //       log_index / receipt_index / header_data
        assert_self();
        let initial_storage = env::storage_usage();

        let proof_key = proof.get_key();
        assert!(
            !self.used_events.contains(&proof_key),
            "Event cannot be reused for depositing."
        );
        self.used_events.insert(&proof_key);
        let current_storage = env::storage_usage();
        let required_deposit =
            Balance::from(current_storage - initial_storage) * env::storage_byte_cost();

        env::log(format!("RecordProof:{}", hex::encode(proof_key)).as_bytes());
        required_deposit
    }

    /// Admin method to set metadata with admin/controller access
    pub fn set_metadata(
        &mut self,
        address: String,
        name: Option<String>,
        symbol: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
        decimals: Option<u8>,
        icon: Option<String>,
    ) -> Promise {
        assert!(self.controller_or_self());
        ext_bridge_token::set_metadata(
            name,
            symbol,
            reference,
            reference_hash,
            decimals,
            icon,
            &self.get_bridge_token_account_id(address),
            env::attached_deposit(),
            env::prepaid_gas() - OUTER_SET_METADATA_GAS,
        )
    }

    /// Map between tokens and timestamp `t`, where `t` stands for the
    /// block on Ethereum where the metadata for given token was emitted.
    fn token_metadata_last_update(&mut self) -> UnorderedMap<String, u64> {
        UnorderedMap::new(TOKEN_TIMESTAMP_MAP_PREFIX.to_vec())
    }

    /// Factory Controller. Controller has extra privileges inside this contract.
    pub fn controller(&self) -> Option<AccountId> {
        env::storage_read(CONTROLLER_STORAGE_KEY)
            .map(|value| String::from_utf8(value).expect("Invalid controller account id"))
    }

    pub fn set_controller(&mut self, controller: AccountId) {
        assert!(self.controller_or_self());
        assert!(env::is_valid_account_id(controller.as_bytes()));
        env::storage_write(CONTROLLER_STORAGE_KEY, controller.as_bytes());
    }

    pub fn controller_or_self(&self) -> bool {
        let caller = env::predecessor_account_id();
        caller == env::current_account_id()
            || self
                .controller()
                .map(|controller| controller == caller)
                .unwrap_or(false)
    }

    /// Ethereum Metadata Connector. This is the address where the contract that emits metadata from tokens
    /// on ethereum is deployed. Address is encoded as hex.
    pub fn metadata_connector(&self) -> Option<String> {
        env::storage_read(METADATA_CONNECTOR_ETH_ADDRESS_STORAGE_KEY)
            .map(|value| String::from_utf8(value).expect("Invalid metadata connector address"))
    }

    pub fn set_metadata_connector(&mut self, metadata_connector: String) {
        assert!(self.controller_or_self());
        validate_eth_address(metadata_connector.clone());
        env::storage_write(
            METADATA_CONNECTOR_ETH_ADDRESS_STORAGE_KEY,
            metadata_connector.as_bytes(),
        );
    }
}

admin_controlled::impl_admin_controlled!(BridgeTokenFactory, paused);

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::panic;

    use near_sdk::{MockedBlockchain, testing_env};
    use near_sdk::env::sha256;
    use near_sdk::test_utils::VMContextBuilder;
    use uint::rustc_hex::{FromHex, ToHex};

    use super::*;

    const UNPAUSE_ALL: Mask = 0;

    macro_rules! inner_set_env {
        ($builder:ident) => {
            $builder
        };

        ($builder:ident, $key:ident:$value:expr $(,$key_tail:ident:$value_tail:expr)*) => {
            {
               $builder.$key($value.try_into().unwrap());
               inner_set_env!($builder $(,$key_tail:$value_tail)*)
            }
        };
    }

    macro_rules! set_env {
        ($($key:ident:$value:expr),* $(,)?) => {
            let mut builder = VMContextBuilder::new();
            let mut builder = &mut builder;
            builder = inner_set_env!(builder, $($key: $value),*);
            testing_env!(builder.build());
        };
    }

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
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        set_env!(
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE,
        );
        contract.deploy_bridge_token(token_locker());
    }

    #[test]
    #[should_panic]
    fn test_fail_deposit_no_token() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        set_env!(
            predecessor_account_id: alice(),
            attached_deposit: env::storage_byte_cost() * 1000
        );
        contract.deposit(sample_proof());
    }

    #[test]
    fn test_deploy_bridge_token() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2,
        );

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
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        set_env!(
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(token_locker());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: format!("{}.{}", token_locker(), bridge_token_factory())
        );

        let address = validate_eth_address(token_locker());
        assert_eq!(
            contract.finish_withdraw(1_000, token_locker()),
            ResultType::Withdraw {
                amount: 1_000,
                token: address,
                recipient: address
            }
        );
    }

    #[test]
    fn deploy_bridge_token_paused() {
        set_env!(predecessor_account_id: alice());

        // User alice can deploy a new bridge token
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(ethereum_address_from_id(0));

        // Admin pause deployment of new token
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.set_paused(PAUSE_DEPLOY_TOKEN);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        // Admin can still deploy new tokens after paused
        contract.deploy_bridge_token(ethereum_address_from_id(1));

        // User alice can't deploy a new bridge token when it is paused
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        panic::catch_unwind(move || {
            contract.deploy_bridge_token(ethereum_address_from_id(2));
        })
        .unwrap_err();
    }

    #[test]
    fn only_admin_can_pause() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        // Admin can pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        contract.set_paused(0b1111);

        // Alice can't pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
        );

        panic::catch_unwind(move || {
            contract.set_paused(0);
        })
        .unwrap_err();
    }

    #[test]
    fn deposit_paused() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        contract.deposit(create_proof(token_locker(), erc20_address.clone()));

        // Pause deposit
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.set_paused(PAUSE_DEPOSIT);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        // Check it is NOT possible to use deposit while the contract is paused
        panic::catch_unwind(move || {
            contract.deposit(create_proof(token_locker(), erc20_address.clone()));
        })
        .unwrap_err();
    }

    /// Check after all is paused deposit is not available
    #[test]
    fn all_paused() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        contract.deposit(create_proof(token_locker(), erc20_address.clone()));

        // Pause everything
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.set_paused(PAUSE_DEPLOY_TOKEN | PAUSE_DEPOSIT);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        // Check it is NOT possible to use deposit while the contract is paused
        panic::catch_unwind(move || {
            contract.deposit(create_proof(token_locker(), erc20_address));
        })
        .unwrap_err();
    }

    /// Check after all is paused and unpaused deposit works
    #[test]
    fn no_paused() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        contract.deposit(create_proof(token_locker(), erc20_address.clone()));

        // Pause everything
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        contract.set_paused(PAUSE_DEPLOY_TOKEN | PAUSE_DEPOSIT);
        contract.set_paused(UNPAUSE_ALL);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        // Check the deposit works after pausing and unpausing everything
        contract.deposit(create_proof(token_locker(), erc20_address));
    }
}
