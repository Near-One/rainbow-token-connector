use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::FungibleToken;
use near_contract_standards::storage_management::{
    StorageBalance, StorageBalanceBounds, StorageManagement,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LazyOption;
use near_sdk::json_types::U128;
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault, PromiseOrValue};
use near_sdk::{log, require, Balance, Promise};

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
pub struct Contract {
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
    storage_deposit: Option<U128>,
}

// example from near
const DATA_IMAGE_SVG_NEAR_ICON: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 288 288'%3E%3Cg id='l' data-name='l'%3E%3Cpath d='M187.58,79.81l-30.1,44.69a3.2,3.2,0,0,0,4.75,4.2L191.86,103a1.2,1.2,0,0,1,2,.91v80.46a1.2,1.2,0,0,1-2.12.77L102.18,77.93A15.35,15.35,0,0,0,90.47,72.5H87.34A15.34,15.34,0,0,0,72,87.84V201.16A15.34,15.34,0,0,0,87.34,216.5h0a15.35,15.35,0,0,0,13.08-7.31l30.1-44.69a3.2,3.2,0,0,0-4.75-4.2L96.14,186a1.2,1.2,0,0,1-2-.91V104.61a1.2,1.2,0,0,1,2.12-.77l89.55,107.23a15.35,15.35,0,0,0,11.71,5.43h3.13A15.34,15.34,0,0,0,216,201.16V87.84A15.34,15.34,0,0,0,200.66,72.5h0A15.35,15.35,0,0,0,187.58,79.81Z'/%3E%3C/g%3E%3C/svg%3E";

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new_default_meta(
        owner_id: AccountId,
        name: String,
        symbol: String,
        total_supply: U128,
        storage_deposit: Option<U128>,
    ) -> Self {
        Self::new(
            owner_id,
            total_supply,
            FungibleTokenMetadata {
                spec: FT_METADATA_SPEC.to_string(),
                name,
                symbol,
                icon: Some(DATA_IMAGE_SVG_NEAR_ICON.to_string()),
                reference: None,
                reference_hash: None,
                decimals: 24,
            },
            storage_deposit,
        )
    }

    #[init]
    pub fn new(
        owner_id: AccountId,
        total_supply: U128,
        metadata: FungibleTokenMetadata,
        storage_deposit: Option<U128>,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");

        metadata.assert_valid();
        let mut this = Self {
            token: FungibleToken::new(b"a".to_vec()),
            metadata: LazyOption::new(b"m".to_vec(), Some(&metadata)),
            storage_deposit,
        };
        this.token.internal_register_account(&owner_id);
        this.token.internal_deposit(&owner_id, total_supply.into());
        this
    }

    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        if self.token.accounts.get(&account_id).is_none() {
            self.token.internal_register_account(&account_id);
        };

        self.token.internal_deposit(&account_id, amount.into());
    }

    pub fn burn(&mut self, account_id: AccountId, amount: U128) {
        self.token.internal_withdraw(&account_id, amount.into());
    }
}

// main implementation for token and storage
near_contract_standards::impl_fungible_token_core!(Contract, token);

#[near_bindgen]
impl FungibleTokenMetadataProvider for Contract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.get().unwrap()
    }
}

#[near_bindgen]
impl StorageManagement for Contract {
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        #[allow(unused_variables)] registration_only: Option<bool>,
    ) -> StorageBalance {
        let amount: Balance = env::attached_deposit();
        let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
        if self.token.accounts.contains_key(&account_id) {
            log!("The account is already registered, refunding the deposit");
            if amount > 0 {
                Promise::new(env::predecessor_account_id()).transfer(amount);
            }
        } else {
            let min_balance = self.storage_balance_bounds().min.0;
            if amount < min_balance {
                env::panic_str("The attached deposit is less than the minimum storage balance");
            }

            self.token.internal_register_account(&account_id);
            let refund = amount - min_balance;
            if refund > 0 {
                Promise::new(env::predecessor_account_id()).transfer(refund);
            }
        }
        self.token.storage_balance_of(account_id).unwrap()
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: Option<U128>) -> StorageBalance {
        self.token.storage_withdraw(amount)
    }

    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        #[allow(unused_variables)]
        if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
            true
        } else {
            false
        }
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        if let Some(storage_deposit) = self.storage_deposit {
            StorageBalanceBounds {
                min: storage_deposit,
                max: Some(storage_deposit),
            }
        } else {
            self.token.storage_balance_bounds()
        }
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
    }
}

#[cfg(test)]
mod tests {
    use near_sdk::test_utils::test_env::{alice, bob};
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{env, testing_env, Balance};

    use super::*;

    const TOTAL_SUPPLY: Balance = 1_000_000_000_000_000;

    fn init() -> (VMContextBuilder, AccountId, Contract) {
        // get VM builer
        let context = VMContextBuilder::new();
        // account for contract
        let contract_account = alice();
        // init the contract
        let contract = Contract::new_default_meta(
            contract_account.clone(),
            String::from("Mock Token"),
            String::from("MOCK"),
            TOTAL_SUPPLY.into(),
        );
        (context, contract_account, contract)
    }

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn check_total_supply() {
        let (context, _contract_account, contract) = init();
        testing_env!(context.build());
        assert_eq!(contract.ft_total_supply(), 1_000_000_000_000_000.into());
    }

    #[test]
    fn test_mint_bob() {
        let (context, _, mut contract) = init();
        testing_env!(context.build());
        let bob_account = bob();
        contract.mint(bob_account.clone(), (TOTAL_SUPPLY / 100).into());
        assert_eq!(
            contract.ft_balance_of(bob_account),
            (TOTAL_SUPPLY / 100).into()
        )
    }

    #[test]
    fn test_burn_bob() {
        let (context, _, mut contract) = init();
        testing_env!(context.build());
        let bob_account = bob();
        contract.mint(bob_account.clone(), (TOTAL_SUPPLY / 100).into());
        contract.burn(bob_account.clone(), (TOTAL_SUPPLY / 100).into());
        assert_eq!(contract.ft_balance_of(bob_account), 0.into())
    }

    #[test]
    fn test_transfer() {
        let mut context = get_context(accounts(2));
        testing_env!(context.build());
        let mut contract = Contract::new_default_meta(
            accounts(2),
            String::from("Mock Token"),
            String::from("MOCK"),
            TOTAL_SUPPLY.into(),
        );
        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(contract.storage_balance_bounds().min.into())
            .predecessor_account_id(accounts(1))
            .build());
        // Paying for account registration, aka storage deposit
        contract.storage_deposit(None, None);

        testing_env!(context
            .storage_usage(env::storage_usage())
            .attached_deposit(1)
            .predecessor_account_id(accounts(2))
            .build());

        let transferred_tokens = TOTAL_SUPPLY / 100;
        contract.ft_transfer(
            accounts(1),
            transferred_tokens.into(),
            Some("you have received some tokens ".to_string()),
        );

        testing_env!(context
            .storage_usage(env::storage_usage())
            .account_balance(env::account_balance())
            .is_view(true)
            .attached_deposit(0)
            .build());

        assert_eq!(
            contract.ft_balance_of(accounts(2)).0,
            (TOTAL_SUPPLY - transferred_tokens)
        );
        assert_eq!(contract.ft_balance_of(accounts(1)).0, transferred_tokens);
    }

    #[test]
    fn test_ft_metadata() {
        let context = get_context(accounts(2));
        testing_env!(context.build());
        let contract = Contract::new_default_meta(
            accounts(2),
            String::from("Mock Token"),
            String::from("MOCK"),
            TOTAL_SUPPLY.into(),
        );
        let some_metadata = contract.ft_metadata();
        let contract_metadata = contract.metadata.get().unwrap();
        assert_eq!(some_metadata.spec, contract_metadata.spec);
        assert_eq!(some_metadata.name, contract_metadata.name);
        assert_eq!(some_metadata.symbol, contract_metadata.symbol);
        assert_eq!(some_metadata.icon, contract_metadata.icon);
        assert_eq!(some_metadata.decimals, contract_metadata.decimals);
    }
}
