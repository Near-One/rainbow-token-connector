use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::{env, near_bindgen, AccountId};

use near_lib::token::{FungibleToken, Token};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct BridgeToken {
    controller: AccountId,
    token: Token,
}

impl Default for BridgeToken {
    fn default() -> Self {
        panic!("Bridge Token should be initialized before usage")
    }
}

#[near_bindgen]
impl BridgeToken {
    #[init]
    pub fn new() -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            controller: env::predecessor_account_id(),
            token: Token::new(env::predecessor_account_id(), 0u128),
        }
    }

    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        assert_eq!(env::predecessor_account_id(), self.controller, "Only controller can call mint");
        self.token.mint(account_id, amount.into());
    }

    pub fn burn(&mut self, account_id: AccountId, amount: U128) {
        assert_eq!(env::predecessor_account_id(), self.controller, "Only controller can call burn");
        self.token.burn(account_id, amount.into());
    }
}

#[near_bindgen]
impl FungibleToken for BridgeToken {
    fn inc_allowance(&mut self, escrow_account_id: String, amount: U128) {
        self.token.inc_allowance(escrow_account_id, amount.into());
    }

    fn dec_allowance(&mut self, escrow_account_id: String, amount: U128) {
        self.token.dec_allowance(escrow_account_id, amount.into());
    }

    fn transfer_from(&mut self, owner_id: String, new_owner_id: String, amount: U128) {
        self.token
            .transfer_from(owner_id, new_owner_id, amount.into());
    }

    fn transfer(&mut self, new_owner_id: String, amount: U128) {
        self.token.transfer(new_owner_id, amount.into());
    }

    fn get_total_supply(&self) -> U128 {
        self.token.get_total_supply().into()
    }

    fn get_balance(&self, owner_id: String) -> U128 {
        self.token.get_balance(owner_id).into()
    }

    fn get_allowance(&self, owner_id: String, escrow_account_id: String) -> U128 {
        self.token.get_allowance(owner_id, escrow_account_id).into()
    }
}
