use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde_json::json;
use near_sdk::{
    assert_one_yocto, env, ext_contract, near_bindgen, require, AccountId, Balance, Gas,
    PanicOnDefault, Promise, PromiseOrValue, PublicKey, StorageUsage,
};

/// Gas to call finish withdraw method on factory.
const FINISH_WITHDRAW_GAS: Gas = Gas(Gas::ONE_TERA.0 * 50);
const OUTER_UPGRADE_GAS: Gas = Gas(Gas::ONE_TERA.0 * 15);
const NO_DEPOSIT: Balance = 0;
const CURRENT_STATE_VERSION: u32 = 2;

pub type Mask = u128;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct BridgeToken {
    controller: AccountId,
    token: FungibleToken,
    name: String,
    symbol: String,
    reference: String,
    reference_hash: Base64VecU8,
    decimals: u8,
    paused: Mask,
    icon: Option<String>,
    new_controller: Option<AccountId>
}

#[ext_contract(ext_bridge_token_factory)]
pub trait ExtBridgeTokenFactory {
    #[result_serializer(borsh)]
    fn finish_withdraw(
        &self,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: String,
    ) -> Promise;
}

#[near_bindgen]
impl BridgeToken {
    #[init]
    pub fn new() -> Self {
        let current_account_id = env::current_account_id();
        let (_eth_address, factory_account) = current_account_id
            .as_str()
            .split_once(".")
            .unwrap_or_else(|| env::panic_str("Invalid token address"));

        require!(
            env::predecessor_account_id().as_str() == factory_account,
            "Only the factory account can init this contract"
        );

        Self {
            controller: env::predecessor_account_id(),
            token: FungibleToken::new(b"t".to_vec()),
            name: String::default(),
            symbol: String::default(),
            reference: String::default(),
            reference_hash: Base64VecU8(vec![]),
            decimals: 0,
            paused: Mask::default(),
            icon: None,
            new_controller: None,
        }
    }

    pub fn set_metadata(
        &mut self,
        name: Option<String>,
        symbol: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
        decimals: Option<u8>,
        icon: Option<String>,
    ) {
        // Only owner can change the metadata
        require!(self.controller_or_self());

        name.map(|name| self.name = name);
        symbol.map(|symbol| self.symbol = symbol);
        reference.map(|reference| self.reference = reference);
        reference_hash.map(|reference_hash| self.reference_hash = reference_hash);
        decimals.map(|decimals| self.decimals = decimals);
        icon.map(|icon| self.icon = Some(icon));
    }

    #[payable]
    pub fn mint(&mut self,
                account_id: AccountId,
                amount: U128,
                msg: Option<String>) -> PromiseOrValue<U128> {
        assert_eq!(
            env::predecessor_account_id(),
            self.controller,
            "Only controller can call mint"
        );

        self.storage_deposit(Some(account_id.clone()), None);
        if let Some(msg) = msg {
            self.token
                .internal_deposit(&env::predecessor_account_id(), amount.into());

            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.token.internal_deposit(&account_id, amount.into());
            PromiseOrValue::Value(amount)
        }
    }

    pub fn burn(&mut self, amount: U128) {
        assert_eq!(
            env::predecessor_account_id(),
            self.controller,
            "Only controller can call burn"
        );

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
    }

    #[payable]
    pub fn withdraw(&mut self, amount: U128, recipient: String) -> Promise {
        require!(!self.is_paused());
        assert_one_yocto();
        Promise::new(env::predecessor_account_id()).transfer(1);

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());

        ext_bridge_token_factory::ext(self.controller.clone())
            .with_static_gas(FINISH_WITHDRAW_GAS)
            .finish_withdraw(env::predecessor_account_id(), amount.into(), recipient)
    }

    pub fn set_new_controller(&mut self, new_controller: Option<AccountId>) {
        require!(self.controller_or_self());
        self.new_controller = new_controller;
    }

    pub fn update_controller(&mut self) {
        require!(Some(env::predecessor_account_id()) == self.new_controller);
        self.controller = env::predecessor_account_id();
        self.new_controller = None;
    }

    pub fn account_storage_usage(&self) -> StorageUsage {
        self.token.account_storage_usage
    }

    /// Return true if the caller is either controller or self
    pub fn controller_or_self(&self) -> bool {
        let caller = env::predecessor_account_id();
        caller == self.controller || caller == env::current_account_id()
    }

    pub fn is_paused(&self) -> bool {
        self.paused != 0 && !self.controller_or_self()
    }

    pub fn set_paused(&mut self, paused: bool) {
        require!(self.controller_or_self());
        self.paused = if paused { 1 } else { 0 };
    }

    pub fn upgrade_and_migrate(&self) {
        require!(
            self.controller_or_self(),
            "Only the controller or self can update the code"
        );

        // Receive the code directly from the input to avoid the
        // GAS overhead of deserializing parameters
        let code = env::input().unwrap_or_else(|| panic!("ERR_NO_INPUT"));
        // Deploy the contract code.
        let promise_id = env::promise_batch_create(&env::current_account_id());
        env::promise_batch_action_deploy_contract(promise_id, &code);
        // Call promise to migrate the state.
        // Batched together to fail upgrade if migration fails.
        env::promise_batch_action_function_call(
            promise_id,
            "migrate",
            &json!({ "from_version": CURRENT_STATE_VERSION })
                .to_string()
                .into_bytes(),
            NO_DEPOSIT,
            env::prepaid_gas() - env::used_gas() - OUTER_UPGRADE_GAS,
        );
        env::promise_return(promise_id);
    }

    /// Attach a new full access to the current contract.
    pub fn attach_full_access_key(&mut self, public_key: PublicKey) -> Promise {
        require!(self.controller_or_self());
        Promise::new(env::current_account_id()).add_full_access_key(public_key)
    }

    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }
}

near_contract_standards::impl_fungible_token_core!(BridgeToken, token);
near_contract_standards::impl_fungible_token_storage!(BridgeToken, token);

#[near_bindgen]
impl FungibleTokenMetadataProvider for BridgeToken {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            icon: self.icon.clone(),
            reference: Some(self.reference.clone()),
            reference_hash: Some(self.reference_hash.clone()),
            decimals: self.decimals,
        }
    }
}

// Migration

#[derive(BorshDeserialize, BorshSerialize)]
pub struct BridgeTokenV0 {
    controller: AccountId,
    token: FungibleToken,
    name: String,
    symbol: String,
    reference: String,
    reference_hash: Base64VecU8,
    decimals: u8,
    paused: Mask,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct BridgeTokenV1 {
    controller: AccountId,
    token: FungibleToken,
    name: String,
    symbol: String,
    reference: String,
    reference_hash: Base64VecU8,
    decimals: u8,
    paused: Mask,
    icon: Option<String>,
}

impl From<BridgeTokenV0> for BridgeToken {
    fn from(obj: BridgeTokenV0) -> Self {
        #[allow(deprecated)]
        Self {
            controller: obj.controller,
            token: obj.token,
            name: obj.name,
            symbol: obj.symbol,
            reference: obj.reference,
            reference_hash: obj.reference_hash,
            decimals: obj.decimals,
            paused: obj.paused,
            icon: None,
            new_controller: None,
        }
    }
}

impl From<BridgeTokenV1> for BridgeToken {
    fn from(obj: BridgeTokenV1) -> Self {
        #[allow(deprecated)]
        Self {
            controller: obj.controller,
            token: obj.token,
            name: obj.name,
            symbol: obj.symbol,
            reference: obj.reference,
            reference_hash: obj.reference_hash,
            decimals: obj.decimals,
            paused: obj.paused,
            icon: obj.icon,
            new_controller: None,
        }
    }
}

#[near_bindgen]
impl BridgeToken {
    /// This function can only be called from the factory or from the contract itself.
    #[init(ignore_state)]
    pub fn migrate(from_version: u32) -> Self {
        if from_version == 0 {
            // Adding icon as suggested here: https://nomicon.io/Standards/FungibleToken/Metadata.html
            let old_state: BridgeTokenV0 = env::state_read().expect("Contract isn't initialized");
            let new_state: BridgeToken = old_state.into();
            assert!(new_state.controller_or_self());
            new_state
        } else if from_version == 1 {
            let old_state: BridgeTokenV1 = env::state_read().expect("Contract isn't initialized");
            let new_state: BridgeToken = old_state.into();
            assert!(new_state.controller_or_self());
            new_state
        } else {
            env::state_read().unwrap()
        }
    }
}
