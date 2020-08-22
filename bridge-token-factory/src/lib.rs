use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::{env, ext_contract, near_bindgen, AccountId, Balance, Promise};

mod prover;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Price per 1 byte of storage from mainnet genesis config.
const STORAGE_PRICE_PER_BYTE: Balance = 100000000000000000000;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct BridgeTokenFactory {
    /// The account of the prover that we can use to prove
    pub prover_account: AccountId,
    /// Address of the Ethereum locker contract.
    pub locker_address: [u8; 20],
    /// Hashes of the events that were already used.
    pub used_events: UnorderedSet<Vec<u8>>,
}

impl Default for BridgeTokenFactory {
    fn default() -> Self {
        panic!("Fun token should be initialized before usage")
    }
}

#[ext_contract(ext_bridge_token)]
pub trait ExtBridgeToken {
    #[result_serializer(borsh)]
    fn finish_mint(
        &self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: U128,
    ) -> Promise;
}

#[near_bindgen]
impl BridgeTokenFactory {
    /// Initializes the contract.
    /// `prover_account`: NEAR account of the Near Prover contract;
    /// `locker_address`: Ethereum address of the locker contract, in hex.
    #[init]
    pub fn new(prover_account: AccountId, locker_address: String) -> Self {
        let data =
            hex::decode(locker_address).expect("`locker_address` should be a valid hex string.");
        assert_eq!(data.len(), 20, "`locker_address` should be 20 bytes long");
        let mut locker_address = [0u8; 20];
        locker_address.copy_from_slice(&data);
        assert!(!env::state_exists(), "Already initialized");
        Self {
            prover_account,
            locker_address,
            used_events: UnorderedSet::new(b"u".to_vec()),
        }
    }

    /// Mint the token, increasing the total supply given the proof that the mirror token was locked
    /// on the Ethereum blockchain.
    #[payable]
    pub fn mint(&mut self, #[serializer(borsh)] proof: Proof) -> Promise {
        let initial_storage = env::storage_usage();
        self.record_proof(&proof);
        let current_storage = env::storage_usage();
        let attached_deposit = env::attached_deposit();
        let required_deposit =
            Balance::from(current_storage - initial_storage) * STORAGE_PRICE_PER_BYTE;
        let leftover_deposit = attached_deposit - required_deposit;
        let Proof {
            log_index,
            log_entry_data,
            receipt_index,
            receipt_data,
            header_data,
            proof,
        } = proof;
        let event = EthEventData::from_log_entry_data(&log_entry_data);
        assert_eq!(
            event.locker_address,
            self.locker_address,
            "Event's address {} does not match locker address of this token {}",
            hex::encode(&event.locker_address),
            hex::encode(&self.locker_address),
        );
        env::log(format!("{}", event).as_bytes());
        let EthEventData {
            recipient, amount, ..
        } = event;
        prover::verify_log_entry(
            log_index,
            log_entry_data,
            receipt_index,
            receipt_data,
            header_data,
            proof,
            false, // Do not skip bridge call. This is only used for development and diagnostics.
            &self.prover_account,
            0,
            env::prepaid_gas() / 3,
        )
        .then(ext_fungible_token::finish_mint(
            recipient,
            amount.into(),
            &env::current_account_id(),
            leftover_deposit,
            env::prepaid_gas() / 3,
        ))
    }

    /// Finish minting once the proof was successfully validated. Can only be called by the contract
    /// itself.
    #[payable]
    pub fn finish_mint(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] new_owner_id: AccountId,
        #[serializer(borsh)] amount: U128,
    ) {
        let initial_storage = env::storage_usage();
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Finish transfer is only allowed to be called by the contract itself"
        );
        assert!(verification_success, "Failed to verify the proof");

        let mut account = self.get_account(&new_owner_id);
        let amount: Balance = amount.into();
        account.balance += amount;
        self.total_supply += amount;
        self.set_account(&new_owner_id, &account);
        self.refund_storage(initial_storage);
    }

    /// Burn given amount of tokens and unlock it on the Ethereum side for the recipient address.
    /// We return the amount as u128 and the address of the beneficiary as `[u8; 20]` for ease of
    /// processing on Solidity side.
    #[result_serializer(borsh)]
    pub fn burn(&mut self, amount: U128, recipient: String) -> (U128, [u8; 20]) {
        let owner = env::predecessor_account_id();
        let mut account = self.get_account(&owner);
        assert!(account.balance >= amount.0, "Not enough balance");
        account.balance -= amount.0;
        self.total_supply -= amount.0;
        self.set_account(&owner, &account);
        let recipient = hex::decode(recipient).expect("recipient should be a hex");
        assert_eq!(
            recipient.len(),
            20,
            "Recipient should be a 20-bytes long address"
        );
        let mut raw_recipient = [0u8; 20];
        raw_recipient.copy_from_slice(&recipient);
        (amount, raw_recipient)
    }

    /// Record proof to make sure it is not re-used later for minting.
    fn record_proof(&mut self, proof: &Proof) {
        let mut data = proof.log_index.try_to_vec().unwrap();
        data.extend(proof.receipt_index.try_to_vec().unwrap());
        data.extend(proof.header_data.clone());
        let key = env::sha256(&data);
        assert!(
            !self.used_events.contains(&key),
            "Event cannot be reused for minting."
        );
        self.used_events.insert(&key);
    }
}