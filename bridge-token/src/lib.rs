use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::FungibleToken;
use near_plugins::{only, pause, FullAccessKeyFallback, Ownable, Pausable, Upgradable};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{
    assert_one_yocto, env, ext_contract, near_bindgen, AccountId, Balance, Gas, PanicOnDefault,
    Promise, PromiseOrValue, StorageUsage,
};
use std::convert::TryInto;

const NO_DEPOSIT: Balance = 0;

/// Gas to call finish withdraw method on factory.
const FINISH_WITHDRAW_GAS: Gas = Gas(50 * Gas::ONE_TERA.0);

#[near_bindgen]
#[derive(
    BorshDeserialize,
    BorshSerialize,
    PanicOnDefault,
    Pausable,
    Ownable,
    Upgradable,
    FullAccessKeyFallback,
)]
pub struct BridgeToken {
    controller: AccountId,
    token: FungibleToken,
    name: String,
    symbol: String,
    reference: String,
    reference_hash: Base64VecU8,
    decimals: u8,
    // Deprecated field. Requires migration to be removed.
    __paused: u128,
    #[cfg(feature = "migrate_icon")]
    icon: Option<String>,
}

#[ext_contract(ext_bridge_token_factory)]
pub trait ExtBridgeTokenFactory {
    #[result_serializer(borsh)]
    fn finish_withdraw(
        &self,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: AccountId,
    ) -> Promise;
}

#[near_bindgen]
impl BridgeToken {
    #[init]
    pub fn new() -> Self {
        Self {
            controller: env::predecessor_account_id(),
            token: FungibleToken::new(b"t".to_vec()),
            name: String::default(),
            symbol: String::default(),
            reference: String::default(),
            reference_hash: Base64VecU8(vec![]),
            decimals: 0,
            __paused: Default::default(),
            #[cfg(feature = "migrate_icon")]
            icon: None,
        }
    }

    #[only(owner)]
    pub fn set_metadata(
        &mut self,
        name: Option<String>,
        symbol: Option<String>,
        reference: Option<String>,
        reference_hash: Option<Base64VecU8>,
        decimals: Option<u8>,
        icon: Option<String>,
    ) {
        name.map(|name| self.name = name);
        symbol.map(|symbol| self.symbol = symbol);
        reference.map(|reference| self.reference = reference);
        reference_hash.map(|reference_hash| self.reference_hash = reference_hash);
        decimals.map(|decimals| self.decimals = decimals);
        #[cfg(feature = "migrate_icon")]
        icon.map(|icon| self.icon = Some(icon));
        #[cfg(not(feature = "migrate_icon"))]
        icon.map(|_| {
            env::log("Icon was provided, but it's not supported for the token".as_bytes())
        });
    }

    #[payable]
    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        assert_eq!(
            env::predecessor_account_id(),
            self.controller,
            "Only controller can call mint"
        );

        self.storage_deposit(Some(account_id.clone()), None);
        self.token.internal_deposit(&account_id, amount.into());
    }

    #[pause]
    #[payable]
    pub fn withdraw(&mut self, amount: U128, recipient: String) -> Promise {
        assert_one_yocto();

        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());

        ext_bridge_token_factory::finish_withdraw(
            amount.into(),
            recipient.try_into().unwrap(),
            self.controller.clone(),
            NO_DEPOSIT,
            FINISH_WITHDRAW_GAS,
        )
    }

    pub fn account_storage_usage(&self) -> StorageUsage {
        self.token.account_storage_usage
    }

    /// Return true if the caller is either controller or self
    pub fn controller_or_self(&self) -> bool {
        let caller = env::predecessor_account_id();
        caller == self.controller || caller == env::current_account_id()
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
            #[cfg(feature = "migrate_icon")]
            icon: self.icon.clone(),
            #[cfg(not(feature = "migrate_icon"))]
            icon: None,
            reference: Some(self.reference.clone()),
            reference_hash: Some(self.reference_hash.clone()),
            decimals: self.decimals,
        }
    }
}

// Migration

#[cfg(feature = "migrate_icon")]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct BridgeTokenV0 {
    controller: AccountId,
    token: FungibleToken,
    name: String,
    symbol: String,
    reference: String,
    reference_hash: Base64VecU8,
    decimals: u8,
    __paused: u128,
}

#[cfg(feature = "migrate_icon")]
impl From<BridgeTokenV0> for BridgeToken {
    fn from(obj: BridgeTokenV0) -> Self {
        Self {
            controller: obj.controller,
            token: obj.token,
            name: obj.name,
            symbol: obj.symbol,
            reference: obj.reference,
            reference_hash: obj.reference_hash,
            decimals: obj.decimals,
            __paused: obj.__paused,
            icon: None,
        }
    }
}

#[cfg(feature = "migrate_icon")]
#[near_bindgen]
impl BridgeToken {
    /// Adding icon as suggested here: https://nomicon.io/Standards/FungibleToken/Metadata.html
    /// This function can only be called from the factory or from the contract itself.
    #[init(ignore_state)]
    pub fn migrate_nep_148_add_icon() -> Self {
        let old_state: BridgeTokenV0 = env::state_read()
            .expect("State is not compatible with BridgeTokenV0. Migration has not been applied.");
        let new_state: BridgeToken = old_state.into();
        assert!(new_state.controller_or_self());
        new_state
    }
}
