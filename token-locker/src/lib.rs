use near_plugins::{Pausable, Ownable};
use near_plugins_derive::pause;
use std::convert::TryInto;

use near_contract_standards::fungible_token::metadata::FungibleTokenMetadata;
use near_contract_standards::storage_management::StorageBalance;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{UnorderedMap, UnorderedSet};
use near_sdk::json_types::U128;
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Balance, BorshStorageKey, Gas, PanicOnDefault,
    Promise, PromiseOrValue,
};

use bridge_common::prover::{
    ext_prover, validate_eth_address, EthAddress, Proof, FT_TRANSFER_CALL_GAS, FT_TRANSFER_GAS,
    NO_DEPOSIT, STORAGE_BALANCE_CALL_GAS, VERIFY_LOG_ENTRY_GAS,
};
use bridge_common::{parse_recipient, result_types, Recipient};
use whitelist::WhitelistMode;

use crate::unlock_event::EthUnlockedEvent;

mod token_receiver;
mod unlock_event;
mod whitelist;

/// Gas to call finish withdraw method.
/// This doesn't cover the gas required for calling transfer method.
const FINISH_WITHDRAW_GAS: Gas = Gas(Gas::ONE_TERA.0 * 30);

/// Gas to call finish deposit method.
const FT_FINISH_DEPOSIT_GAS: Gas = Gas(Gas::ONE_TERA.0 * 10);

/// Gas for fetching metadata of token.
const FT_GET_METADATA_GAS: Gas = Gas(Gas::ONE_TERA.0 * 10);

/// Gas for emitting metadata info.
const FT_FINISH_LOG_METADATA_GAS: Gas = Gas(Gas::ONE_TERA.0 * 30);

/// Gas to call storage balance callback method.
const FT_STORAGE_BALANCE_CALLBACK_GAS: Gas = Gas(Gas::ONE_TERA.0 * 10);

pub type Mask = u128;

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    UsedEvents,
    WhitelistTokens,
    WhitelistAccounts,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault, Ownable, Pausable)]
pub struct Contract {
    /// The account of the prover that we can use to prove.
    pub prover_account: AccountId,
    /// Ethereum address of the token factory contract, in hex.
    pub eth_factory_address: EthAddress,
    /// Hashes of the events that were already used.
    pub used_events: UnorderedSet<Vec<u8>>,
    /// Mask determining all paused functions
    #[deprecated]
    paused: Mask,
    /// Mapping whitelisted tokens to their mode
    pub whitelist_tokens: UnorderedMap<AccountId, WhitelistMode>,
    /// Mapping whitelisted accounts to their whitelisted tokens by using combined key {token}:{account}
    pub whitelist_accounts: UnorderedSet<String>,
    /// The mode of the whitelist check
    pub is_whitelist_mode_enabled: bool,
}

#[ext_contract(ext_self)]
pub trait ExtContract {
    #[result_serializer(borsh)]
    fn finish_deposit(
        &self,
        #[serializer(borsh)] token: AccountId,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: EthAddress,
    ) -> result_types::Lock;

    #[result_serializer(borsh)]
    fn finish_withdraw(
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
    fn finish_log_metadata(
        &self,
        #[callback] metadata: FungibleTokenMetadata,
        token_id: AccountId,
    ) -> result_types::Metadata;

    fn storage_balance_callback(
        &self,
        #[callback] storage_balance: Option<StorageBalance>,
        #[serializer(borsh)] proof: Proof,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] recipient: AccountId,
        #[serializer(borsh)] amount: Balance,
    );
}

#[ext_contract(ext_token)]
pub trait ExtToken {
    fn ft_transfer(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
    ) -> PromiseOrValue<U128>;

    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128>;

    fn ft_metadata(&self) -> FungibleTokenMetadata;

    fn storage_balance_of(&mut self, account_id: Option<AccountId>) -> Option<StorageBalance>;
}

#[near_bindgen]
impl Contract {
    #[init]
    /// `prover_account`: NEAR account of the Near Prover contract;
    /// `factory_address`: Ethereum address of the token factory contract, in hex.
    pub fn new(prover_account: AccountId, factory_address: String) -> Self {
        #[allow(deprecated)]
        let mut contract = Self {
            prover_account,
            used_events: UnorderedSet::new(StorageKey::UsedEvents),
            eth_factory_address: validate_eth_address(factory_address),
            paused: Mask::default(),
            whitelist_tokens: UnorderedMap::new(StorageKey::WhitelistTokens),
            whitelist_accounts: UnorderedSet::new(StorageKey::WhitelistAccounts),
            is_whitelist_mode_enabled: true,
        };

        contract.owner_set(Some(near_sdk::env::predecessor_account_id()));
        contract
    }

    /// Logs into the result of this transaction a Metadata for given token.
    pub fn log_metadata(&self, token_id: AccountId) -> Promise {
        ext_token::ext(token_id.clone())
            .with_static_gas(FT_GET_METADATA_GAS)
            .ft_metadata()
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(FT_FINISH_LOG_METADATA_GAS)
                    .finish_log_metadata(token_id),
            )
    }

    /// Emits `result_types::Metadata` with Metadata of the given token.
    #[private]
    #[result_serializer(borsh)]
    pub fn finish_log_metadata(
        &self,
        #[callback] metadata: FungibleTokenMetadata,
        token_id: AccountId,
    ) -> result_types::Metadata {
        result_types::Metadata::new(
            token_id.to_string(),
            metadata.name,
            metadata.symbol,
            metadata.decimals,
            env::block_height(),
        )
    }

    /// Withdraw funds from NEAR Token Locker.
    /// Receives proof of burning tokens on the other side. Validates it and releases funds.
    #[payable]
    #[pause]
    pub fn withdraw(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        let event = EthUnlockedEvent::from_log_entry_data(&proof.log_entry_data);
        assert_eq!(
            event.eth_factory_address,
            self.eth_factory_address,
            "Event's address {} does not match eth factory address of this token {}",
            hex::encode(&event.eth_factory_address),
            hex::encode(&self.eth_factory_address),
        );

        let Recipient {
            target: recipient_account_id,
            message: _,
        } = parse_recipient(event.recipient);

        ext_token::ext(event.token.clone().try_into().unwrap())
            .with_static_gas(STORAGE_BALANCE_CALL_GAS)
            .storage_balance_of(Some(recipient_account_id.clone()))
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(
                        FT_STORAGE_BALANCE_CALLBACK_GAS
                            + FINISH_WITHDRAW_GAS
                            + FT_TRANSFER_CALL_GAS,
                    )
                    .with_attached_deposit(env::attached_deposit())
                    .storage_balance_callback(
                        proof,
                        event.token,
                        recipient_account_id,
                        event.amount,
                    ),
            )
    }

    #[private]
    pub fn storage_balance_callback(
        &self,
        #[callback] storage_balance: Option<StorageBalance>,
        #[serializer(borsh)] proof: Proof,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] recipient: AccountId,
        #[serializer(borsh)] amount: Balance,
    ) -> Promise {
        assert!(
            storage_balance.is_some(),
            "The account {} is not registered",
            recipient
        );

        let proof_1 = proof.clone();
        ext_prover::ext(self.prover_account.clone())
            .with_static_gas(VERIFY_LOG_ENTRY_GAS)
            .with_attached_deposit(NO_DEPOSIT)
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
                    .with_attached_deposit(env::attached_deposit())
                    .with_static_gas(FINISH_WITHDRAW_GAS + FT_TRANSFER_CALL_GAS)
                    .finish_withdraw(token, recipient.to_string(), amount, proof_1),
            )
    }

    #[private]
    #[result_serializer(borsh)]
    pub fn finish_deposit(
        &self,
        #[serializer(borsh)] token: AccountId,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: EthAddress,
    ) -> result_types::Lock {
        result_types::Lock::new(token.into(), amount, recipient)
    }

    #[private]
    #[payable]
    pub fn finish_withdraw(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] new_owner_id: String,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] proof: Proof,
    ) -> Promise {
        assert!(verification_success, "Failed to verify the proof");
        let required_deposit = self.record_proof(&proof);

        assert!(env::attached_deposit() >= required_deposit);

        let Recipient { target, message } = parse_recipient(new_owner_id);

        env::log_str(
            format!(
                "Finish deposit. Token:{} Target:{} Message:{:?}",
                token, target, message
            )
            .as_str(),
        );

        match message {
            Some(message) => ext_token::ext(token.try_into().unwrap())
                .with_attached_deposit(near_sdk::ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(target, amount.into(), None, message),
            None => ext_token::ext(token.try_into().unwrap())
                .with_attached_deposit(near_sdk::ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(target, amount.into(), None),
        }
    }

    /// Checks whether the provided proof is already used.
    pub fn is_used_proof(&self, #[serializer(borsh)] proof: Proof) -> bool {
        self.used_events.contains(&proof.get_key())
    }

    /// Record proof to make sure it is not re-used later for anther withdrawal.
    #[private]
    fn record_proof(&mut self, proof: &Proof) -> Balance {
        // TODO: Instead of sending the full proof (clone only relevant parts of the Proof)
        //       log_index / receipt_index / header_data
        let initial_storage = env::storage_usage();

        let proof_key = proof.get_key();
        assert!(
            !self.used_events.contains(&proof_key),
            "Event cannot be reused for withdrawing."
        );
        self.used_events.insert(&proof_key);
        let current_storage = env::storage_usage();
        let required_deposit =
            Balance::from(current_storage - initial_storage) * env::storage_byte_cost();

        env::log_str(&format!("RecordProof:{}", hex::encode(proof_key)));
        required_deposit
    }

    #[private]
    pub fn update_factory_address(&mut self, factory_address: String) {
        self.eth_factory_address = validate_eth_address(factory_address);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::panic;

    use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
    use near_sdk::env::sha256;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use uint::rustc_hex::{FromHex, ToHex};

    use super::*;

    pub fn accounts(id: usize) -> AccountId {
        AccountId::new_unchecked(near_sdk::test_utils::accounts(id).to_string() + ".near")
    }

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

    fn prover() -> AccountId {
        "prover.near".parse().unwrap()
    }

    fn bridge_token_factory() -> AccountId {
        "bridge.near".parse().unwrap()
    }

    fn token_locker() -> String {
        "6b175474e89094c44da98b954eedeac495271d0f".to_string()
    }

    /// Generate a valid ethereum address.
    fn ethereum_address_from_id(id: u8) -> String {
        let mut buffer = vec![id];
        sha256(buffer.as_mut())
            .into_iter()
            .take(20)
            .collect::<Vec<_>>()
            .to_hex()
    }

    fn create_proof(locker: String, token: String, recipient: String) -> Proof {
        let event_data = EthUnlockedEvent {
            eth_factory_address: locker
                .from_hex::<Vec<_>>()
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),

            token,
            sender: "00005474e89094c44da98b954eedeac495271d0f".to_string(),
            amount: 1000,
            recipient,
            token_eth_address: validate_eth_address(
                "0123456789abcdefdeadbeef0123456789abcdef".to_string(),
            ),
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
    fn test_lock_unlock_token() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());
        set_env!(predecessor_account_id: accounts(1));
        contract.set_token_whitelist_mode(accounts(1), WhitelistMode::CheckToken);
        contract.ft_on_transfer(accounts(2), U128(1_000_000), ethereum_address_from_id(0));
        contract.finish_deposit(
            accounts(1).into(),
            1_000_000,
            validate_eth_address(ethereum_address_from_id(0)),
        );

        let proof = create_proof(token_locker(), accounts(1).into(), "bob.near".to_string());
        set_env!(attached_deposit: env::storage_byte_cost() * 1000);
        contract.withdraw(proof.clone());
        contract.finish_withdraw(
            true,
            accounts(1).into(),
            accounts(2).into(),
            1_000_000,
            proof,
        );
    }

    #[test]
    fn test_lock_unlock_token_with_custom_recipient_message() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());
        set_env!(predecessor_account_id: accounts(1));
        contract.set_token_whitelist_mode(accounts(1), WhitelistMode::CheckToken);
        contract.ft_on_transfer(accounts(2), U128(1_000_000), ethereum_address_from_id(0));
        contract.finish_deposit(
            accounts(1).into(),
            1_000_000,
            validate_eth_address(ethereum_address_from_id(0)),
        );

        let proof = create_proof(
            token_locker(),
            accounts(1).into(),
            "bob.near:some message".to_string(),
        );
        set_env!(attached_deposit: env::storage_byte_cost() * 1000);
        contract.withdraw(proof.clone());
        contract.finish_withdraw(
            true,
            accounts(1).into(),
            accounts(2).into(),
            1_000_000,
            proof,
        );
    }

    #[test]
    fn test_only_admin_can_pause() {
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        let mut contract = Contract::new(prover(), token_locker());

        // Admin can pause
        contract.pa_pause_feature("deposit".to_string());

        // Admin can unpause.
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        contract.pa_unpause_feature("deposit".to_string());

        // Alice can't pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: accounts(0),
        );

        panic::catch_unwind(move || {
            contract.pa_pause_feature("deposit".to_string());
        })
        .unwrap_err();
    }

    #[test]
    #[should_panic(expected = "The token is blocked")]
    fn test_blocked_token() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        let token_account = accounts(1);
        let sender_account = accounts(2);
        set_env!(predecessor_account_id: token_account.clone());
        contract.set_token_whitelist_mode(token_account, WhitelistMode::Blocked);
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    #[should_panic(expected = "does not exist in the whitelist")]
    fn test_account_not_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        let token_account = accounts(1);
        let sender_account = accounts(2);
        set_env!(predecessor_account_id: token_account);
        contract.set_token_whitelist_mode(accounts(1), WhitelistMode::CheckAccountAndToken);
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    #[should_panic(expected = "The token is not whitelisted")]
    fn test_token_not_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        let token_account = accounts(1);
        let sender_account = accounts(2);
        set_env!(predecessor_account_id: token_account);
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    fn test_account_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        let token_account = accounts(1);
        let sender_account = accounts(2);
        contract
            .set_token_whitelist_mode(token_account.clone(), WhitelistMode::CheckAccountAndToken);
        contract.add_account_to_whitelist(token_account.clone(), sender_account.clone());

        set_env!(predecessor_account_id: token_account);
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    #[should_panic(expected = "does not exist in the whitelist")]
    fn test_remove_account_from_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        let token_account = accounts(1);
        let sender_account = accounts(2);
        contract
            .set_token_whitelist_mode(token_account.clone(), WhitelistMode::CheckAccountAndToken);
        contract.add_account_to_whitelist(token_account.clone(), sender_account.clone());

        set_env!(predecessor_account_id: token_account.clone());
        contract.ft_on_transfer(
            sender_account.clone(),
            U128(1_000_000),
            ethereum_address_from_id(0),
        );

        contract.remove_account_from_whitelist(token_account.clone(), sender_account.clone());
        contract.ft_on_transfer(
            sender_account.clone(),
            U128(1_000_000),
            ethereum_address_from_id(0),
        );
    }

    #[test]
    fn test_tokens_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        let whitelist_tokens = ["token1.near", "token2.near", "token3.near"];

        for token_id in whitelist_tokens {
            contract.set_token_whitelist_mode(token_id.parse().unwrap(), WhitelistMode::CheckToken);
        }

        for token_id in whitelist_tokens {
            let token_account: AccountId = token_id.parse().unwrap();
            let sender_account = accounts(2);
            set_env!(predecessor_account_id: token_account);
            contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
        }
    }

    #[test]
    fn test_accounts_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        let whitelist_tokens = ["token1.near", "token2.near", "token3.near"];
        let whitelist_accounts = ["account1.near", "account2.near", "account3.near"];

        for token_id in whitelist_tokens {
            let token_account: AccountId = token_id.parse().unwrap();
            contract.set_token_whitelist_mode(
                token_account.clone(),
                WhitelistMode::CheckAccountAndToken,
            );

            for account_id in whitelist_accounts {
                let sender_account: AccountId = account_id.parse().unwrap();
                contract.add_account_to_whitelist(token_account.clone(), sender_account.clone());
            }
        }

        for token_id in whitelist_tokens {
            for account_id in whitelist_accounts {
                let token_account: AccountId = token_id.parse().unwrap();
                let sender_account: AccountId = account_id.parse().unwrap();
                set_env!(predecessor_account_id: token_account);
                contract.ft_on_transfer(
                    sender_account,
                    U128(1_000_000),
                    ethereum_address_from_id(0),
                );
            }
        }
    }
}
