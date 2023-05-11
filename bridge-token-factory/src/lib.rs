use near_plugins::{
    access_control, access_control_any, pause, AccessControlRole, AccessControllable, Pausable,
    Upgradable,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{UnorderedMap, UnorderedSet};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Balance, BorshStorageKey, Gas, PanicOnDefault,
    Promise, PromiseOrValue, PublicKey, ONE_NEAR,
};

pub use bridge_common::prover::{is_eth_address, validate_eth_address, Proof};
use bridge_common::{parse_recipient, prover::*, result_types, Recipient};
pub use lock_event::EthLockedEvent;
pub use log_metadata_event::TokenMetadataEvent;

mod lock_event;
mod log_metadata_event;

const BRIDGE_TOKEN_BINARY: &'static [u8] = include_bytes!(std::env!(
    "BRIDGE_TOKEN",
    "Set BRIDGE_TOKEN to be the path of the bridge token binary"
));

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = ONE_NEAR * 3; // 3e24yN, 3N

/// Gas to initialize BridgeToken contract.
const BRIDGE_TOKEN_NEW: Gas = Gas(Gas::ONE_TERA.0 * 10);

/// Gas to call mint method on bridge token.
const MINT_GAS: Gas = Gas(Gas::ONE_TERA.0 * 10);

/// Gas to call finish deposit method.
/// This doesn't cover the gas required for calling mint method.
const FINISH_DEPOSIT_GAS: Gas = Gas(Gas::ONE_TERA.0 * 30);

/// Gas to call finish update_metadata method.
const FINISH_UPDATE_METADATA_GAS: Gas = Gas(Gas::ONE_TERA.0 * 5);

/// Amount of gas used by set_metadata in the factory, without taking into account
/// the gas consumed by the promise.
const OUTER_SET_METADATA_GAS: Gas = Gas(Gas::ONE_TERA.0 * 15);

/// Amount of gas used by bridge token to set the metadata.
const SET_METADATA_GAS: Gas = Gas(Gas::ONE_TERA.0 * 5);

/// Amount of gas used by bridge token to pause withdraw.
const SET_PAUSED_GAS: Gas = Gas(Gas::ONE_TERA.0 * 5);

/// Amount of gas used upgrade and migrate bridge token.
const UPGRADE_TOKEN_GAS: Gas = Gas(Gas::ONE_TERA.0 * 200);

/// Controller storage key.
const CONTROLLER_STORAGE_KEY: &[u8] = b"aCONTROLLER";

/// Metadata connector address storage key.
const METADATA_CONNECTOR_ETH_ADDRESS_STORAGE_KEY: &[u8] = b"aM_CONNECTOR";

/// Prefix used to store a map between tokens and timestamp `t`, where `t` stands for the
/// block on Ethereum where the metadata for given token was emitted.
/// The prefix is made specially short since it becomes more expensive with larger prefixes.
const TOKEN_TIMESTAMP_MAP_PREFIX: &[u8] = b"aTT";

const FEE_DECIMAL_PRECISION: u128 = 1000000;
const AURORA_ID: &str = "aurora";

pub type Mask = u128;

#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    PauseManager,
    UpgradableManager,
    UpgradableCodeStager,
    UpgradableCodeDeployer,
    UpgradableDurationManager,
    ConfigManager,
    UnrestrictedDeposit,
    UnrestrictedDeployBridgeToken,
    MetadataManager,
    FeeSetter,
    FeeClaimer,
}

#[derive(
    Default, BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq,
)]
pub struct DepositTokenBounds {
    lower_bound: u128,
    upper_bound: u128,
}

#[derive(
    Default, BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq,
)]
pub struct WithdrawTokenBounds {
    lower_bound: u128,
    upper_bound: u128,
}

#[derive(
    Default, BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq,
)]
pub struct DepositFeePercentage {
    eth_to_near: u128,
    eth_to_aurora: u128,
}

#[derive(
    Default, BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq,
)]
pub struct WithdrawFeePercentage {
    near_to_eth: u128,
    aurora_to_eth: u128,
}

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    DepositBounds,
    DepositFeePercentage,
    WithdrawBounds,
    WithdrawFeePercentage,
    WithdrawFeePerSilo,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault, Pausable, Upgradable)]
#[access_control(role_type(Role))]
#[pausable(manager_roles(Role::PauseManager))]
#[upgradable(access_control_roles(
    code_stagers(Role::UpgradableCodeStager, Role::UpgradableManager),
    code_deployers(Role::UpgradableCodeDeployer, Role::UpgradableManager),
    duration_initializers(Role::UpgradableDurationManager, Role::UpgradableManager),
    duration_update_stagers(Role::UpgradableDurationManager, Role::UpgradableManager),
    duration_update_appliers(Role::UpgradableDurationManager, Role::UpgradableManager),
))]
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
    #[deprecated]
    paused: Mask,
    /// Fee amount bound for deposit.
    pub deposit_fee_bound: UnorderedMap<String, DepositTokenBounds>,
    /// Fee amount bound for withdraw
    pub withdraw_fee_bound: UnorderedMap<String, WithdrawTokenBounds>,
    /// Fee percentage of each token for deposit
    pub deposit_fee_percentage: UnorderedMap<String, DepositFeePercentage>,
    /// Fee percentage of each token for withdraw
    pub withdraw_fee_percentage: UnorderedMap<String, WithdrawFeePercentage>,
    /// Fee percentage of each token for withdraw to Aurora as per silo
    pub withdraw_fee_percentage_per_silo: UnorderedMap<AccountId, u128>,
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
        #[serializer(borsh)] new_owner_id: String,
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

#[ext_contract(ext_bridge_token)]
pub trait ExtBridgeToken {
    fn mint(&self, account_id: AccountId, amount: U128);

    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
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

    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);

    fn set_paused(&mut self, paused: bool);

    fn upgrade_and_migrate(&mut self, code: &[u8]);
}

pub fn assert_self() {
    assert_eq!(env::predecessor_account_id(), env::current_account_id());
}

pub fn is_aurora_engine_account(withdrawer: AccountId) -> bool {
    let mut parts: Vec<&str> = withdrawer.as_str().split('.').collect();
    println!("PARTS: {:?}", parts);
    if parts.len() < 2 {
        return withdrawer.as_str() == AURORA_ID;
    } else if parts.len() == 2 {
        let first_data = parts[0];
        let master_account = parts.pop().unwrap();
        if !is_eth_address(first_data.to_string()) {
            return master_account == AURORA_ID;
        };
    }

    return false;
}

#[near_bindgen]
impl BridgeTokenFactory {
    /// Initializes the contract.
    /// `prover_account`: NEAR account of the Near Prover contract;
    /// `locker_address`: Ethereum address of the locker contract, in hex.
    #[init]
    pub fn new(prover_account: AccountId, locker_address: String) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        #[allow(deprecated)]
        let mut contract = Self {
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
            deposit_fee_bound: UnorderedMap::new(StorageKey::DepositBounds),
            withdraw_fee_bound: UnorderedMap::new(StorageKey::WithdrawBounds),
            deposit_fee_percentage: UnorderedMap::new(StorageKey::DepositFeePercentage),
            withdraw_fee_percentage: UnorderedMap::new(StorageKey::WithdrawFeePercentage),
            withdraw_fee_percentage_per_silo: UnorderedMap::new(StorageKey::WithdrawFeePerSilo),
        };

        contract.acl_init_super_admin(near_sdk::env::predecessor_account_id());
        contract
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

        ext_prover::ext(self.prover_account.clone())
            .with_static_gas(VERIFY_LOG_ENTRY_GAS)
            .verify_log_entry(
                proof.log_index,
                proof.log_entry_data,
                proof.receipt_index,
                proof.receipt_data,
                proof.header_data,
                proof.proof,
                false, // Do not skip bridge call. This is only used for development and diagnostics.
            )
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(FINISH_UPDATE_METADATA_GAS + SET_METADATA_GAS)
                    .with_attached_deposit(env::attached_deposit())
                    .finish_updating_metadata(
                        event.token,
                        event.name,
                        event.symbol,
                        event.decimals,
                        event.timestamp,
                    ),
            )
    }

    /// Deposit from Ethereum to NEAR based on the proof of the locked tokens.
    /// Must attach enough NEAR funds to cover for storage of the proof.
    #[payable]
    #[pause(except(roles(Role::UnrestrictedDeposit)))]
    pub fn deposit(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
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

        ext_prover::ext(self.prover_account.clone())
            .with_static_gas(VERIFY_LOG_ENTRY_GAS)
            .verify_log_entry(
                proof.log_index,
                proof.log_entry_data,
                proof.receipt_index,
                proof.receipt_data,
                proof.header_data,
                proof.proof,
                false, // Do not skip bridge call. This is only used for development and diagnostics.
            )
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(FINISH_DEPOSIT_GAS + MINT_GAS + FT_TRANSFER_CALL_GAS)
                    .with_attached_deposit(env::attached_deposit())
                    .finish_deposit(event.token, event.recipient, event.amount, proof_1),
            )
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

        env::log_str(&format!(
            "Finish updating metadata. Name: {} Symbol: {:?} Decimals: {:?} at: {:?}",
            name, symbol, decimals, timestamp
        ));

        let reference = None;
        let reference_hash = None;
        let icon = None;

        ext_bridge_token::ext(self.get_bridge_token_account_id(token.clone()))
            .with_static_gas(SET_METADATA_GAS)
            .with_attached_deposit(env::attached_deposit() - required_deposit)
            .set_metadata(
                name.into(),
                symbol.into(),
                reference,
                reference_hash,
                decimals.into(),
                icon,
            );
    }

    pub fn get_deposit_token_fee_bound(&self, token: &String) -> Option<DepositTokenBounds> {
        self.deposit_fee_bound.get(token)
    }

    pub fn get_deposit_token_fee_percentage(&self, token: &String) -> Option<DepositFeePercentage> {
        self.deposit_fee_percentage.get(token)
    }

    pub fn get_withdraw_token_fee_bound(&self, token: &String) -> Option<WithdrawTokenBounds> {
        self.withdraw_fee_bound.get(token)
    }

    pub fn get_withdraw_token_fee_percentage(
        &self,
        token: &String,
    ) -> Option<WithdrawFeePercentage> {
        self.withdraw_fee_percentage.get(token)
    }

    pub fn get_withdraw_fee_percentage_per_silo(&self, silo_account: &AccountId) -> Option<u128> {
        self.withdraw_fee_percentage_per_silo.get(silo_account)
    }

    //token here should be ethereum address
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_deposit_fee_bound(
        &mut self,
        token: &String,
        upper_bound: u128,
        lower_bound: u128,
    ) -> DepositTokenBounds {
        let _ = validate_eth_address(token.clone());
        self.deposit_fee_bound.insert(
            token,
            &DepositTokenBounds {
                lower_bound,
                upper_bound,
            },
        );
        DepositTokenBounds {
            lower_bound,
            upper_bound,
        }
    }

    //this should be added as per: 10% -> 0.1 = 0.1*10^6
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_deposit_fee_percentage(
        &mut self,
        token: &String,
        eth_to_near: u128,
        eth_to_aurora: u128,
    ) -> DepositFeePercentage {
        let _ = validate_eth_address(token.clone());
        self.deposit_fee_percentage.insert(
            token,
            &DepositFeePercentage {
                eth_to_near,
                eth_to_aurora,
            },
        );
        DepositFeePercentage {
            eth_to_near,
            eth_to_aurora,
        }
    }

    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_withdraw_fee_bound(
        &mut self,
        token: &String,
        upper_bound: u128,
        lower_bound: u128,
    ) -> WithdrawTokenBounds {
        let _ = validate_eth_address(token.clone());
        self.withdraw_fee_bound.insert(
            token,
            &WithdrawTokenBounds {
                lower_bound,
                upper_bound,
            },
        );
        WithdrawTokenBounds {
            lower_bound,
            upper_bound,
        }
    }

    //this should be added as per: 10% -> 0.1 = 0.1*10^6
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_withdraw_fee_percentage(
        &mut self,
        token: &String,
        near_to_eth: u128,
        aurora_to_eth: u128,
    ) -> WithdrawFeePercentage {
        let _ = validate_eth_address(token.clone());
        self.withdraw_fee_percentage.insert(
            token,
            &WithdrawFeePercentage {
                near_to_eth,
                aurora_to_eth,
            },
        );
        WithdrawFeePercentage {
            near_to_eth,
            aurora_to_eth,
        }
    }

    //this should be added as per: 10% -> 0.1 = 0.1*10^6
    #[access_control_any(roles(Role::FeeSetter))]
    pub fn set_withdraw_fee_percentage_per_silo(
        &mut self,
        silo_address: &AccountId,
        fee_percent: u128,
    ) -> u128 {
        let _ = is_aurora_engine_account(silo_address.clone());
        self.withdraw_fee_percentage_per_silo.insert(
            silo_address,
           &fee_percent,
        );
        fee_percent
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

        env::log_str(&format!(
            "Finish deposit. Target:{} Message:{:?}",
            target, message
        ));

        let deposit_fee_bound = self.get_deposit_token_fee_bound(&token);
        let deposit_fee_percentage =
            self.get_deposit_token_fee_percentage(&token)
                .unwrap_or(DepositFeePercentage {
                    eth_to_aurora: 0,
                    eth_to_near: 0,
                });

        let amount_to_transfer: u128;
        let mut fee_amount: u128;

        match deposit_fee_bound {
            Some(token_bounds) => {
                match message.clone() {
                    Some(_message) => {
                        fee_amount =
                            (amount * deposit_fee_percentage.eth_to_aurora) / FEE_DECIMAL_PRECISION;
                    }
                    None => {
                        fee_amount =
                            (amount * deposit_fee_percentage.eth_to_near) / FEE_DECIMAL_PRECISION;
                        // 0.01 for ETH -> NEAR
                    }
                }
                if fee_amount < token_bounds.lower_bound {
                    fee_amount = token_bounds.lower_bound;
                } else if fee_amount > token_bounds.upper_bound {
                    fee_amount = token_bounds.upper_bound;
                }
            }
            None => {
                fee_amount = 0;
            }
        }
        amount_to_transfer = amount - fee_amount;

        match message {
            Some(message) => ext_bridge_token::ext(self.get_bridge_token_account_id(token.clone()))
                .with_static_gas(MINT_GAS)
                .with_attached_deposit(env::attached_deposit() - required_deposit)
                .mint(env::current_account_id(), amount.into())
                .then(
                    ext_bridge_token::ext(self.get_bridge_token_account_id(token))
                        .with_static_gas(FT_TRANSFER_CALL_GAS)
                        .with_attached_deposit(1)
                        .ft_transfer_call(target, amount_to_transfer.into(), None, message),
                ),
            None => ext_bridge_token::ext(self.get_bridge_token_account_id(token.clone()))
                .with_static_gas(MINT_GAS)
                .with_attached_deposit(env::attached_deposit() - required_deposit)
                .mint(target, amount_to_transfer.into())
                .then(
                    ext_bridge_token::ext(self.get_bridge_token_account_id(token))
                        .with_static_gas(MINT_GAS)
                        .with_attached_deposit(env::attached_deposit() - required_deposit)
                        .mint(env::current_account_id(), fee_amount.into()),
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
        #[serializer(borsh)] withdrawer: AccountId,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: String,
    ) -> result_types::Withdraw {
        let token = env::predecessor_account_id();
        let parts: Vec<&str> = token.as_str().split('.').collect();
        assert_eq!(
            token.to_string(),
            format!("{}.{}", parts[0], env::current_account_id()),
            "Only sub accounts of BridgeTokenFactory can call this method."
        );
        assert!(
            self.tokens.contains(&parts[0].to_string()),
            "Such BridgeToken does not exist."
        );
        let token_address = validate_eth_address(parts[0].to_string());
        let recipient_address = validate_eth_address(recipient);

        let withdraw_fee_bound = self.get_withdraw_token_fee_bound(&parts[0].to_string());
        let withdraw_fee_percentage = self
            .get_withdraw_token_fee_percentage(&parts[0].to_string())
            .unwrap_or(WithdrawFeePercentage {
                near_to_eth: 0,
                aurora_to_eth: 0,
            });

        let amount_to_transfer: u128;
        let mut fee_amount: u128;

        match withdraw_fee_bound {
            Some(token_bounds) => {
                if is_aurora_engine_account(withdrawer.clone()) {
                    let silo_fee = self.get_withdraw_fee_percentage_per_silo(&withdrawer).unwrap_or(0);
                    if silo_fee != 0{
                        fee_amount =
                            (amount * silo_fee) / FEE_DECIMAL_PRECISION;    
                    } else{
                        fee_amount =
                            (amount * withdraw_fee_percentage.aurora_to_eth) / FEE_DECIMAL_PRECISION;
                    }
                } else {
                    fee_amount =
                        (amount * withdraw_fee_percentage.near_to_eth) / FEE_DECIMAL_PRECISION;
                    // 0.01 for ETH -> NEAR
                }

                if fee_amount < token_bounds.lower_bound {
                    //bound checks
                    fee_amount = token_bounds.lower_bound;
                } else if fee_amount > token_bounds.upper_bound {
                    fee_amount = token_bounds.upper_bound;
                }
            }
            None => {
                fee_amount = 0;
            }
        }

        amount_to_transfer = amount - fee_amount;

        if fee_amount != 0 {
            ext_bridge_token::ext(token)
                .with_static_gas(MINT_GAS)
                .with_attached_deposit(env::attached_deposit())
                .mint(env::current_account_id(), fee_amount.into());
        }

        result_types::Withdraw::new(amount_to_transfer, token_address, recipient_address)
    }

    #[access_control_any(roles(Role::FeeClaimer))]
    pub fn claim_fee(&self, token: AccountId, amount: Balance) {
        ext_bridge_token::ext(token)
            .with_static_gas(FT_TRANSFER_GAS)
            .with_attached_deposit(1)
            .ft_transfer(env::predecessor_account_id(), amount.into(), None);
    }

    #[payable]
    #[pause(except(roles(Role::UnrestrictedDeployBridgeToken)))]
    pub fn deploy_bridge_token(&mut self, address: String) -> Promise {
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
        Promise::new(bridge_token_account_id.parse().unwrap())
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE)
            .add_full_access_key(self.owner_pk.clone())
            .deploy_contract(BRIDGE_TOKEN_BINARY.to_vec())
            .function_call(
                "new".to_string(),
                b"{}".to_vec(),
                NO_DEPOSIT,
                BRIDGE_TOKEN_NEW,
            )
    }

    #[access_control_any(roles(Role::UpgradableCodeDeployer, Role::UpgradableManager))]
    pub fn upgrade_bridge_token(&self, address: String) -> Promise {
        Promise::new(self.get_bridge_token_account_id(address)).function_call(
            "upgrade_and_migrate".to_string(),
            BRIDGE_TOKEN_BINARY.into(),
            0,
            UPGRADE_TOKEN_GAS,
        )
    }

    #[access_control_any(roles(Role::PauseManager))]
    pub fn set_paused_withdraw(&mut self, address: String, paused: bool) -> Promise {
        ext_bridge_token::ext(self.get_bridge_token_account_id(address))
            .with_static_gas(SET_PAUSED_GAS)
            .set_paused(paused)
    }

    pub fn get_bridge_token_account_id(&self, address: String) -> AccountId {
        let address = address.to_lowercase();
        let _ = validate_eth_address(address.clone());
        assert!(
            self.tokens.contains(&address),
            "BridgeToken with such address does not exist."
        );
        format!("{}.{}", address, env::current_account_id())
            .parse()
            .unwrap()
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

        env::log_str(&format!("RecordProof:{}", hex::encode(proof_key)));
        required_deposit
    }

    /// Admin method to set metadata
    #[access_control_any(roles(Role::MetadataManager))]
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
        ext_bridge_token::ext(self.get_bridge_token_account_id(address))
            .with_static_gas(env::prepaid_gas() - OUTER_SET_METADATA_GAS)
            .with_attached_deposit(env::attached_deposit())
            .set_metadata(name, symbol, reference, reference_hash, decimals, icon)
    }

    /// Map between tokens and timestamp `t`, where `t` stands for the
    /// block on Ethereum where the metadata for given token was emitted.
    fn token_metadata_last_update(&mut self) -> UnorderedMap<String, u64> {
        UnorderedMap::new(TOKEN_TIMESTAMP_MAP_PREFIX.to_vec())
    }

    /// Factory Controller. Controller has extra privileges inside this contract.
    pub fn controller(&self) -> Option<AccountId> {
        env::storage_read(CONTROLLER_STORAGE_KEY).map(|value| {
            String::from_utf8(value)
                .expect("Invalid controller account id")
                .parse()
                .unwrap()
        })
    }

    /// Ethereum Metadata Connector. This is the address where the contract that emits metadata from tokens
    /// on ethereum is deployed. Address is encoded as hex.
    pub fn metadata_connector(&self) -> Option<String> {
        env::storage_read(METADATA_CONNECTOR_ETH_ADDRESS_STORAGE_KEY)
            .map(|value| String::from_utf8(value).expect("Invalid metadata connector address"))
    }

    #[access_control_any(roles(Role::ConfigManager))]
    pub fn set_metadata_connector(&mut self, metadata_connector: String) {
        validate_eth_address(metadata_connector.clone());
        env::storage_write(
            METADATA_CONNECTOR_ETH_ADDRESS_STORAGE_KEY,
            metadata_connector.as_bytes(),
        );
    }

    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use std::{convert::TryInto, str::FromStr};
    use std::panic;

    use near_sdk::env::sha256;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use uint::rustc_hex::{FromHex, ToHex};

    use super::*;

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
        "alice.near".parse().unwrap()
    }

    fn fee_setter() -> AccountId {
        "fee_setter.near".parse().unwrap()
    }

    fn bob() -> AccountId {
        "bob.near".parse().unwrap()
    }

    fn prover() -> AccountId {
        "prover".parse().unwrap()
    }

    fn bridge_token_factory() -> AccountId {
        "bridge".parse().unwrap()
    }

    fn pause_manager() -> AccountId {
        "pause_manager".parse().unwrap()
    }

    fn token_locker() -> String {
        "6b175474e89094c44da98b954eedeac495271d0f".to_string()
    }

    fn withdrawer_as_silos() -> AccountId {
        "silo1.aurora".parse().unwrap()
    }

    fn withdrawer_as_native_aurora() -> AccountId {
        "aurora".parse().unwrap()
    }

    fn withdrawer_as_evm_aurora() -> AccountId {
        "6b175474e89094c44da98b954eedeac495271d0f.aurora"
            .parse()
            .unwrap()
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
            recipient: "123".parse().unwrap(),
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
    fn test_fee_token_bound_setter_for_deposit() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());
        let deposit_bound = contract.set_deposit_fee_bound(&token_address, 100, 200);
        let bound = contract
            .get_deposit_token_fee_bound(&token_address)
            .unwrap();
        assert_eq!(
            deposit_bound.lower_bound, bound.lower_bound,
            "Lower bound not matched"
        );
        assert_eq!(
            deposit_bound.upper_bound, bound.upper_bound,
            "Upper bound not matched"
        );
    }

    #[test]
    fn test_withdrawer_is_aurora_account() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let silos_call = is_aurora_engine_account(withdrawer_as_silos());
        let native_aurora_call = is_aurora_engine_account(withdrawer_as_native_aurora());
        let aurora_with_evm_address_call = is_aurora_engine_account(withdrawer_as_evm_aurora());
        assert_eq!(silos_call, true);
        assert_eq!(native_aurora_call, true);
        assert_eq!(aurora_with_evm_address_call, false);
    }

    #[test]
    #[should_panic]
    fn test_fee_token_bound_setter_for_deposit_with_unallowed_role() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        set_env!(predecessor_account_id: bob()); // bob has no role to set fee-bounds);
        contract.set_deposit_fee_bound(&token_address, 100, 200);
    }

    #[test]
    fn test_fee_token_bound_setter_for_withdraw() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(4);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());
        let withdraw_bound = contract.set_withdraw_fee_bound(&token_address, 100, 200);
        let bound = contract
            .get_withdraw_token_fee_bound(&token_address)
            .unwrap();
        assert_eq!(
            withdraw_bound.lower_bound, bound.lower_bound,
            "Lower bound not matched"
        );
        assert_eq!(
            withdraw_bound.upper_bound, bound.upper_bound,
            "Upper bound not matched"
        );
    }

    #[test]
    #[should_panic]
    fn test_fee_token_bound_setter_for_withdraw_with_unallowed_role() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(4);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: bob());
        let withdraw_bound = contract.set_withdraw_fee_bound(&token_address, 100, 200);
        let bound = contract
            .get_withdraw_token_fee_bound(&token_address)
            .unwrap();
        assert_eq!(
            withdraw_bound.lower_bound, bound.lower_bound,
            "Lower bound not matched"
        );
        assert_eq!(
            withdraw_bound.upper_bound, bound.upper_bound,
            "Upper bound not matched"
        );
    }

    #[test]
    fn test_fee_token_percentage_setter_for_deposit() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());
        let deposit_fee_percentage =
            contract.set_deposit_fee_percentage(&token_address, 50000, 20000); //0.05% and 0.02%
        let expected_fee_percentage = contract
            .get_deposit_token_fee_percentage(&token_address)
            .unwrap();
        assert_eq!(
            deposit_fee_percentage.eth_to_aurora, expected_fee_percentage.eth_to_aurora,
            "Aurora -> Eth fee percentage not matched for deposit"
        );
        assert_eq!(
            deposit_fee_percentage.eth_to_near, expected_fee_percentage.eth_to_near,
            "Eth -> Near fee percentage not matched for deposit"
        );
    }

    #[test]
    fn test_fee_token_percentage_setter_for_withdraw() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());
        let withdraw_fee_percentage =
            contract.set_withdraw_fee_percentage(&token_address, 90000, 40000); //0.09% and 0.04%
        let expected_fee_percentage = contract
            .get_withdraw_token_fee_percentage(&token_address)
            .unwrap();
        assert_eq!(
            withdraw_fee_percentage.aurora_to_eth, expected_fee_percentage.aurora_to_eth,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
        assert_eq!(
            withdraw_fee_percentage.near_to_eth, expected_fee_percentage.near_to_eth,
            "Eth -> Near fee percentage not matched for withdraw"
        );
    }

    #[test]
    fn test_withdraw_fee_setter_silo() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: fee_setter());
        let silo_account = AccountId::from_str("silo.aurora").unwrap();
        let withdraw_fee_percentage =
            contract.set_withdraw_fee_percentage_per_silo(&silo_account, 10000000); 
        let expected_fee_percentage = contract
            .get_withdraw_fee_percentage_per_silo(&silo_account)
            .unwrap();
        assert_eq!(
            withdraw_fee_percentage, expected_fee_percentage,
            "Aurora -> Eth fee percentage not matched for withdraw"
        );
    }


    #[test]
    #[should_panic]
    fn test_fee_token_percentage_setter_for_deposit_with_unallowed_role() {
        set_env!(predecessor_account_id: alice(), current_account_id: alice());
        let token_address = ethereum_address_from_id(2);
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        contract.acl_grant_role("FeeSetter".to_string(), fee_setter());
        set_env!(predecessor_account_id: bob());
        let deposit_fee_percentage =
            contract.set_deposit_fee_percentage(&token_address, 50000, 20000); //0.05% and 0.02%
        let fee_percentage = contract
            .get_deposit_token_fee_percentage(&token_address)
            .unwrap();
        assert_eq!(
            deposit_fee_percentage.eth_to_aurora, fee_percentage.eth_to_aurora,
            "Aurora -> Eth fee percentage not matched"
        );
        assert_eq!(
            deposit_fee_percentage.eth_to_near, fee_percentage.eth_to_near,
            "Eth -> Near fee percentage not matched"
        );
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
            contract
                .get_bridge_token_account_id(token_locker())
                .to_string(),
            format!("{}.{}", token_locker(), bridge_token_factory())
        );

        let uppercase_address = "0f5Ea0A652E851678Ebf77B69484bFcD31F9459B".to_string();
        contract.deploy_bridge_token(uppercase_address.clone());
        assert_eq!(
            contract
                .get_bridge_token_account_id(uppercase_address.clone())
                .to_string(),
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
            contract.finish_withdraw(alice(), 1_000, token_locker()),
            result_types::Withdraw::new(1_000, address, address)
        );
    }

    #[test]
    fn deploy_bridge_token_paused() {
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );

        // User alice can deploy a new bridge token
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        assert!(contract
            .acl_grant_role("PauseManager".to_owned(), pause_manager())
            .unwrap());
        let unrestricted_deploy_account: AccountId = "unrestricted_account".parse().unwrap();
        assert!(contract
            .acl_grant_role(
                "UnrestrictedDeployBridgeToken".to_owned(),
                unrestricted_deploy_account.clone()
            )
            .unwrap());
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(ethereum_address_from_id(0));

        // Pause manager pause deployment of new token
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: pause_manager(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.pa_pause_feature("deploy_bridge_token".to_string());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: unrestricted_deploy_account,
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        // Account with role `UnrestrictedDeployBridgeToken` can still deploy new tokens after paused
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
    fn only_pause_manager_can_pause() {
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        assert!(contract
            .acl_grant_role("PauseManager".to_owned(), pause_manager())
            .unwrap());

        // Pause manager can pause
        set_env!(
            current_account_id: pause_manager(),
            predecessor_account_id: pause_manager(),
        );
        assert!(contract.pa_pause_feature("deposit".to_string()));

        // Alice can't pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
        );

        panic::catch_unwind(move || {
            contract.pa_pause_feature("deposit".to_string());
        })
        .unwrap_err();
    }

    #[test]
    fn deposit_paused() {
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        assert!(contract
            .acl_grant_role("PauseManager".to_owned(), pause_manager())
            .unwrap());

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
            predecessor_account_id: pause_manager(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.pa_pause_feature("deposit".to_string());

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
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        assert!(contract
            .acl_grant_role("PauseManager".to_owned(), pause_manager())
            .unwrap());

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
            predecessor_account_id: pause_manager(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.pa_pause_feature("ALL".to_string());

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
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        let mut contract = BridgeTokenFactory::new(prover(), token_locker());
        assert!(contract
            .acl_grant_role("PauseManager".to_owned(), pause_manager())
            .unwrap());

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
            predecessor_account_id: pause_manager(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        contract.pa_pause_feature("ALL".to_string());
        contract.pa_unpause_feature("ALL".to_string());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        // Check the deposit works after pausing and unpausing everything
        contract.deposit(create_proof(token_locker(), erc20_address));
    }
}
