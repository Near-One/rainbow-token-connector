use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{assert_self, env, AccountId};

use crate::*;

#[derive(BorshDeserialize, BorshSerialize, Deserialize, Serialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum WhitelistMode {
    Blocked,
    CheckToken,
    CheckAccountAndToken,
}

fn get_token_account_key(token: AccountId, account: AccountId) -> String {
    format!("{}:{}", token, account)
}

#[near_bindgen]
impl Contract {
    #[private]
    pub fn set_token_whitelist_mode(&mut self, token: AccountId, mode: WhitelistMode) {
        self.whitelist_tokens.insert(&token, &mode);
    }

    #[private]
    pub fn add_account_to_whitelist(&mut self, token: AccountId, account: AccountId) {
        assert!(
            self.whitelist_tokens.get(&token).is_some(),
            "The whitelisted token mode is not set",
        );
        self.whitelist_accounts
            .insert(&get_token_account_key(token, account));
    }

    pub fn check_whitelist_token(&mut self, token: AccountId, account: AccountId) {
        if !self.is_whitelist_mode_enabled {
            return;
        }

        let token_whitelist_mode = self
            .whitelist_tokens
            .get(&token)
            .unwrap_or_else(|| env::panic_str("The token is not whitelisted"));

        match token_whitelist_mode {
            WhitelistMode::CheckAccountAndToken => {
                let token_account_key = get_token_account_key(token, account);
                assert!(
                    self.whitelist_accounts.contains(&token_account_key),
                    "{}",
                    format!(
                        "The {} key does not exist in the whitelist",
                        token_account_key
                    ),
                );
            }
            WhitelistMode::CheckToken => {}
            WhitelistMode::Blocked => env::panic_str("The token is blocked"),
        }
    }
}
