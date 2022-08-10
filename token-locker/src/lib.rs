use std::convert::TryInto;

use admin_controlled::{AdminControlled, Mask};
use near_contract_standards::fungible_token::metadata::FungibleTokenMetadata;
use near_sdk::{AccountId, Balance, env, ext_contract, Gas, near_bindgen, PanicOnDefault, Promise, PromiseOrValue};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedSet;
use near_sdk::json_types::{U128};

use bridge_common::{parse_recipient, Recipient, ResultType};
use bridge_common::prover::{EthAddress, ext_prover, Proof, validate_eth_address, FT_TRANSFER_CALL_GAS, FT_TRANSFER_GAS, NO_DEPOSIT, PAUSE_DEPOSIT, VERIFY_LOG_ENTRY_GAS};
use near_sdk_inner::BorshStorageKey;
use near_sdk_inner::collections::UnorderedMap;
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

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    UsedEvents,
    WhitelistTokens,
    WhitelistAccounts,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    /// The account of the prover that we can use to prove.
    pub prover_account: AccountId,
    /// Ethereum address of the token bridge contract, in hex.
    bridge_address: EthAddress,
    /// Hashes of the events that were already used.
    pub used_events: UnorderedSet<Vec<u8>>,
    /// Mask determining all paused functions
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
        #[serializer(borsh)] recipient: EthAddress
    ) -> ResultType;

    #[result_serializer(borsh)]
    fn finish_withdraw(
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
    fn finish_log_metadata(
        &self,
        #[callback]
        #[serializer(borsh)]
        metadata: FungibleTokenMetadata,
    ) -> ResultType;
}

#[ext_contract(ext_token)]
pub trait ExtToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) -> PromiseOrValue<U128>;

    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128>;

    fn ft_metadata(&self) -> FungibleTokenMetadata;
}

#[near_bindgen]
impl Contract {
    #[init]
    /// `prover_account`: NEAR account of the Near Prover contract;
    /// `bridge_address`: Ethereum address of the token bridge contract, in hex.
    pub fn new(prover_account: AccountId, bridge_address: String) -> Self {
        Self {
            prover_account,
            used_events: UnorderedSet::new(StorageKey::UsedEvents),
            bridge_address: validate_eth_address(bridge_address),
            paused: Mask::default(),
            whitelist_tokens: UnorderedMap::new(StorageKey::WhitelistTokens),
            whitelist_accounts: UnorderedSet::new(StorageKey::WhitelistAccounts),
            is_whitelist_mode_enabled: true,
        }
    }

    /// Logs into the result of this transaction a Metadata for given token.
    pub fn log_metadata(&self, token_id: AccountId) -> Promise {
        ext_token::ext(token_id.clone())
        .with_static_gas(FT_GET_METADATA_GAS)
        .ft_metadata()
            .then(ext_self::ext(token_id)
            .with_static_gas(FT_FINISH_LOG_METADATA_GAS).finish_log_metadata())
    }

    /// Emits `ResultType` with Metadata of the given token.
    #[private]
    #[result_serializer(borsh)]
    pub fn finish_log_metadata(
        &self,
        #[callback]
        #[serializer(borsh)]
        metadata: FungibleTokenMetadata,
    ) -> ResultType {
        ResultType::Metadata {
            token: env::predecessor_account_id().into(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
            block_height: env::block_height(),
        }
    }

    /// Withdraw funds from NEAR Token Locker.
    /// Receives proof of burning tokens on the other side. Validates it and releases funds.
    #[payable]
    pub fn withdraw(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        self.check_not_paused(PAUSE_DEPOSIT);
        let event = EthUnlockedEvent::from_log_entry_data(&proof.log_entry_data);
        assert_eq!(
            event.bridge_address,
            self.bridge_address,
            "Event's address {} does not match locker address of this token {}",
            hex::encode(&event.bridge_address),
            hex::encode(&self.bridge_address),
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
            .then(ext_self::ext(env::current_account_id())
            .with_attached_deposit(env::attached_deposit())
            .with_static_gas( FINISH_WITHDRAW_GAS + FT_TRANSFER_CALL_GAS)
                .finish_withdraw(
                event.token,
                event.recipient,
                event.amount,
                proof_1,
            ))
    }

    #[private]
    #[result_serializer(borsh)]
    pub fn finish_deposit(&self,
                          #[serializer(borsh)] token: AccountId,
                          #[serializer(borsh)] amount: Balance,
                          #[serializer(borsh)] recipient: EthAddress,
    ) -> ResultType {
        ResultType::Lock {
            token: token.into(),
            amount,
            recipient,
        }
    }

    #[private]
    #[payable]
    pub fn finish_withdraw(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] token: String,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] proof: Proof,
    ) -> Promise {
        assert!(verification_success, "Failed to verify the proof");
        let required_deposit = self.record_proof(&proof);

        assert!(
            env::attached_deposit()
                >= required_deposit
        );

        let Recipient { target, message } = parse_recipient(new_owner_id.into());

        env::log_str(format!("Finish deposit. Token:{} Target:{} Message:{:?}", token, target, message).as_str());

        match message {
            Some(message) => ext_token::ext(token.try_into().unwrap())
            .with_attached_deposit(1)
            .with_static_gas(FT_TRANSFER_CALL_GAS)
            .ft_transfer_call(
                    target.try_into().unwrap(),
                    amount.into(),
                    None,
                    message,
                ),
            None => ext_token::ext(token.try_into().unwrap())
            .with_attached_deposit(1)
            .with_static_gas(FT_TRANSFER_GAS)
            .ft_transfer(
                target.into(),
                amount.into(),
                None,
            ),
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
}

admin_controlled::impl_admin_controlled!(Contract, paused);

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::panic;

    use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
    use near_sdk::{MockedBlockchain, testing_env};
    use near_sdk::env::sha256;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
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

    fn prover() -> AccountId {
        "prover".parse().unwrap()
    }

    fn bridge_token_factory() -> AccountId {
        "bridge".parse().unwrap()
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

    fn create_proof(locker: String, token: String) -> Proof {
        let event_data = EthUnlockedEvent {
            bridge_address: locker
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
    fn test_lock_unlock_token() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());
        set_env!(predecessor_account_id: accounts(1));
        contract.ft_on_transfer(accounts(2), U128(1_000_000), ethereum_address_from_id(0));
        contract.finish_deposit(accounts(1).into(), 1_000_000, validate_eth_address(ethereum_address_from_id(0)));

        let proof = create_proof(token_locker(), accounts(1).into());
        set_env!(attached_deposit: env::storage_byte_cost() * 1000);
        contract.withdraw(proof.clone());
        contract.finish_withdraw(true, accounts(1).into(), accounts(2).into(), 1_000_000, proof);
    }

    #[test]
    fn test_only_admin_can_pause() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = Contract::new(prover(), token_locker());

        // Admin can pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        contract.set_paused(0b1111);

        // Admin can unpause.
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        contract.set_paused(UNPAUSE_ALL);

        // Alice can't pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: accounts(0),
        );

        panic::catch_unwind(move || {
            contract.set_paused(0);
        })
            .unwrap_err();
    }
}