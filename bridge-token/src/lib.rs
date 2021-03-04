use std::convert::TryFrom;

use near_contract_standards::fungible_token::FungibleToken;
use near_contract_standards::fungible_token::metadata::{FT_METADATA_SPEC, FungibleTokenMetadata, FungibleTokenMetadataProvider};
use near_sdk::{AccountId, Balance, env, ext_contract, near_bindgen, PanicOnDefault, Promise, PromiseOrValue};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{Base64VecU8, U128, ValidAccountId};

near_sdk::setup_alloc!();

const NO_DEPOSIT: Balance = 0;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct BridgeToken {
    controller: AccountId,
    token: FungibleToken,
    name: String,
    symbol: String,
    reference: String,
    reference_hash: Base64VecU8,
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
    pub fn new(name: String, symbol: String, reference: String, reference_hash: Base64VecU8) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            token: FungibleToken::new(b"t"),
            name,
            symbol,
            reference,
            reference_hash,
            controller: env::predecessor_account_id(),
        }
    }

    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        assert_eq!(
            env::predecessor_account_id(),
            self.controller,
            "Only controller can call mint"
        );
        // TODO: should this always require payment for storage and just return it back if it's already registered?
        if !self.token.ar_is_registered(ValidAccountId::try_from(account_id.clone()).unwrap()) {
            self.token.internal_register_account(&account_id);
        }
        self.token.internal_deposit(&account_id, amount.into());
    }

    pub fn withdraw(&mut self, amount: U128, recipient: String) -> Promise {
        self.token
            .internal_withdraw(&env::predecessor_account_id(), amount.into());
        // TODO: deal with de-allocating storage and sending it back?
        ext_bridge_token_factory::finish_withdraw(
            amount.into(),
            recipient,
            &self.controller,
            NO_DEPOSIT,
            env::prepaid_gas() / 2,
        )
    }
}

near_contract_standards::impl_fungible_token_core!(BridgeToken, token);
near_contract_standards::impl_fungible_token_ar!(BridgeToken, token);

#[near_bindgen]
impl FungibleTokenMetadataProvider for BridgeToken {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            icon: Some(
                "https://near.org/wp-content/themes/near-19/assets/img/brand-icon.png".to_string(),
            ),
            reference: self.reference.clone(),
            reference_hash: self.reference_hash.clone(),
            decimals: 24,
        }
    }
}
