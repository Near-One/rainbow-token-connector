use admin_controlled::{AdminControlled, Mask};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedSet;
use near_sdk::json_types::{Base64VecU8, ValidAccountId, U128};
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Balance, Gas, PanicOnDefault, Promise, PublicKey,
};

use aurora_engine_parameters::*;
use std::convert::TryInto;
use primitive_types::U256;

pub type EthAddress = [u8; 20];

pub fn validate_eth_address(address: String) -> EthAddress {
    let data = hex::decode(address).expect("address should be a valid hex string.");
    assert_eq!(data.len(), 20, "address should bebytes long 20 ");
    let mut result = [0u8; 20];
    result.copy_from_slice(&data);
    result
}

near_sdk::setup_alloc!();

const BRIDGE_TOKEN_BINARY: &'static [u8] = include_bytes!(std::env!(
    "BRIDGE_TOKEN",
    "Set BRIDGE_TOKEN to be the path of the bridge token binary"
));

const NO_DEPOSIT: Balance = 0;

/// Initial balance for the BridgeToken contract to cover storage and related.
const BRIDGE_TOKEN_INIT_BALANCE: Balance = 3_000_000_000_000_000_000_000_000; // 3e24yN, 3N

/// Gas to initialize BridgeToken contract.
const BRIDGE_TOKEN_NEW: Gas = 10_000_000_000_000;

/// Gas to call mint method on bridge token.
const MINT_GAS: Gas = 10_000_000_000_000;

/// Gas to call unlock_erc20_tokens method
const UNLOCK_ERC20_GAS: Gas = 150_000_000_000_000;

// Gas to call get_erc20_metadata method
const GET_METADATA_GAS: Gas = 17_000_000_000_000;

// Gas to call claim method
const CLAIM_GAS: Gas = 17_000_000_000_000;

/// Gas to call finish update_metadata method.
const FINISH_UPDATE_METADATA_GAS: Gas = 6_000_000_000_000;

/// Amount of gas used by set_metadata in the factory, without taking into account
/// the gas consumed by the promise.
const OUTER_SET_METADATA_GAS: Gas = 15_000_000_000_000;

/// Amount of gas used by bridge token to set the metadata.
const SET_METADATA_GAS: Gas = 5_000_000_000_000;

/// Controller storage key.
const CONTROLLER_STORAGE_KEY: &[u8] = b"aCONTROLLER";

/// Selector to call claim function in ERC 20 locker contract
///
/// keccak("claim(address,uint256)".as_bytes())[..4];
pub const LOCKER_CLAIM_SELECTOR: &[u8] = &[170, 211, 236, 150];
/// Selector to call getTokenMetadata function in ERC 20 locker contract
///
/// keccak("getTokenMetadata(address)".as_bytes())[..4];
pub const LOCKER_METADATA_SELECTOR: &[u8] = &[192, 15, 20, 171];
/// Selector to call unlockToken function in ERC 20 locker contract
///
/// keccak("unlockToken(address,uint256,address)".as_bytes())[..4];
pub const LOCKER_UNLOCK_SELECTOR: &[u8] = &[90, 156, 120, 171];

#[derive(Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum ResultType {
    Withdraw {
        amount: Balance,
        token: EthAddress,
        recipient: EthAddress,
    },
    Lock {
        token: String,
        amount: Balance,
        recipient: EthAddress,
    },
}

const PAUSE_DEPLOY_TOKEN: Mask = 1 << 0;
const PAUSE_DEPOSIT: Mask = 1 << 1;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct BridgeTokenFactory {
    /// The account of the aurora engine
    pub aurora_account: AccountId,
    /// Address of the Ethereum locker contract.
    pub locker_address: EthAddress,
    /// Set of created BridgeToken contracts.
    pub tokens: UnorderedSet<String>,
    /// Public key of the account deploying the factory.
    pub owner_pk: PublicKey,
    /// Balance required to register a new account in the BridgeToken
    pub bridge_token_storage_deposit_required: Balance,
    /// Mask determining all paused functions
    paused: Mask,
}

#[ext_contract(ext_self)]
pub trait ExtBridgeTokenFactory {
    #[result_serializer(borsh)]
    fn finish_updating_metadata(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        result: TransactionStatus,
        #[serializer(borsh)] token: String,
    ) -> Promise;
    #[result_serializer(borsh)]
    fn finish_deposit(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        result: SubmitResult,
        #[serializer(borsh)] token: String,
    ) -> Promise;
}

#[ext_contract(ext_fungible_token)]
pub trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[ext_contract(ext_bridge_token)]
pub trait ExtBridgeToken {
    fn mint(&self, account_id: AccountId, amount: U128);

    fn ft_transfer_call(
        &mut self,
        receiver_id: ValidAccountId,
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
}

#[ext_contract(ext_aurora)]
pub trait Aurora {
    #[result_serializer(borsh)]
    fn call(
        &mut self,
        #[serializer(borsh)] input: FunctionCallArgs,
    ) -> Promise<SubmitResult>;

    #[result_serializer(borsh)]
    fn view(
        &mut self,
        #[serializer(borsh)] input: ViewCallArgs,
    ) -> Promise<TransactionStatus>;
}

pub fn assert_self() {
    assert_eq!(env::predecessor_account_id(), env::current_account_id());
}

#[near_bindgen]
impl BridgeTokenFactory {
    /// Initializes the contract.
    /// `aurora_account`: NEAR account of the Aurora engine contract;
    /// `locker_address`: Ethereum address of the locker contract, in hex.
    #[init]
    pub fn new(aurora_account: AccountId, locker_address: String) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            aurora_account,
            locker_address: validate_eth_address(locker_address),
            tokens: UnorderedSet::new(b"t".to_vec()),
            owner_pk: env::signer_account_pk(),
            bridge_token_storage_deposit_required:
                near_contract_standards::fungible_token::FungibleToken::new(b"t".to_vec())
                    .account_storage_usage as Balance
                    * env::storage_byte_cost(),
            paused: Mask::default(),
        }
    }

    pub fn update_metadata(&mut self, token: String) -> Promise {
        assert!(
            self.tokens.contains(&token),
            "Bridge token for {} is not deployed yet",
            token
        );

        let tail = ethabi::encode(&[
            ethabi::Token::Address(validate_eth_address(token.clone()).into()),
        ]);

        let get_metadata_args = ViewCallArgs {
            sender: self.locker_address,
            address: self.locker_address,
            amount: [0; 32],
            input: [LOCKER_METADATA_SELECTOR, tail.as_slice()].concat(),
        };

        ext_aurora::view(
            get_metadata_args,
            &self.aurora_account,
            NO_DEPOSIT,
            GET_METADATA_GAS,
        )
        .then(ext_self::finish_updating_metadata(
            token,
            &env::current_account_id(),
            env::attached_deposit(),
            FINISH_UPDATE_METADATA_GAS + SET_METADATA_GAS,
        ))
    }
    /// Deposit from Aurora to NEAR
    #[payable]
    pub fn deposit(
        &mut self,
        token: String,
        nonce: String,
    ) -> Promise {
        self.check_not_paused(PAUSE_DEPOSIT);

        assert!(
            self.tokens.contains(&token),
            "Bridge token for {} is not deployed yet",
            token
        );

        let tail = ethabi::encode(&[
            ethabi::Token::Address(validate_eth_address(token.clone()).into()),
            ethabi::Token::Uint(U256::from(nonce.as_bytes())),
        ]);

        let call_args = FunctionCallArgs {
            contract: self.locker_address,
            value: WeiU256::default(),
            input: [LOCKER_CLAIM_SELECTOR, tail.as_slice()].concat(),
        };

        ext_aurora::call(
            call_args,
            &self.aurora_account,
            NO_DEPOSIT,
            CLAIM_GAS,
        )
        .then(ext_self::finish_deposit(
            token,
            &env::current_account_id(),
            env::attached_deposit(),
            FINISH_UPDATE_METADATA_GAS + SET_METADATA_GAS,
        ))
    }

    /// Return all registered tokens
    pub fn get_tokens(&self) -> Vec<String> {
        self.tokens.iter().collect::<Vec<_>>()
    }

    pub fn finish_deposit(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        result: SubmitResult,
        #[serializer(borsh)] token: String,
    ) {
        let output: Vec<u8> = match result.status {
            TransactionStatus::Succeed(ret) => ret,
            _other => Vec::new(),
        };

        let mut output_list = ethabi::decode(&[ethabi::ParamType::Uint(128), ethabi::ParamType::String], output.as_slice()).unwrap();
        let amount: u128 = output_list.pop().unwrap().into_uint().unwrap().try_into().unwrap();
        let recipient: String = output_list.pop().unwrap().into_string().unwrap();

        ext_bridge_token::mint(
            recipient,
            amount.into(),
            &self.get_bridge_token_account_id(token),
            env::attached_deposit(),
            MINT_GAS,
        );
    }

    /// Finish updating token metadata.
    /// Can only be called by the contract itself.
    pub fn finish_updating_metadata(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        result: TransactionStatus,
        #[serializer(borsh)] token: String,
    ) {
        let output: Vec<u8> = match result {
            TransactionStatus::Succeed(ret) => ret,
            _other => Vec::new(),
        };

        let mut output_list = ethabi::decode(&[ethabi::ParamType::String, ethabi::ParamType::String, ethabi::ParamType::Uint(8)], output.as_slice()).unwrap();
        let name: String = output_list.pop().unwrap().into_string().unwrap();
        let symbol: String = output_list.pop().unwrap().into_string().unwrap();
        let decimals: u8 = output_list.pop().unwrap().into_uint().unwrap().try_into().unwrap();

        env::log(
            format!(
                "Finish updating metadata. Name: {:?} Symbol: {:?} Decimals: {:?}",
                name, symbol, decimals
            )
            .as_bytes(),
        );

        let reference = None;
        let reference_hash = None;
        let icon = None;

        ext_bridge_token::set_metadata(
            Some(name),
            Some(symbol),
            reference,
            reference_hash,
            Some(decimals),
            icon,
            &self.get_bridge_token_account_id(token.clone()),
            env::attached_deposit(),
            SET_METADATA_GAS,
        );
    }

    /// Burn given amount of tokens and unlock it on the Aurora side for the recipient address.
    /// Caller must be <token_address>.<current_account_id>, where <token_address> exists in the `tokens`.
    #[result_serializer(borsh)]
    pub fn finish_withdraw(
        &mut self,
        #[serializer(borsh)] amount: Balance,
        #[serializer(borsh)] recipient: String,
    ) -> ResultType {
        let token = env::predecessor_account_id();
        let parts: Vec<&str> = token.split(".").collect();
        assert_eq!(
            token,
            format!("{}.{}", parts[0], env::current_account_id()),
            "Only sub accounts of BridgeTokenFactory can call this method."
        );
        assert!(
            self.tokens.contains(&parts[0].to_string()),
            "Such BridgeToken does not exist."
        );
        
        let token_address = validate_eth_address(parts[0].to_string());
        let recipient_address = validate_eth_address(recipient.clone());

        let tail = ethabi::encode(&[
            ethabi::Token::Address(token_address.into()),
            ethabi::Token::Uint(ethabi::Uint::from(amount)),
            ethabi::Token::String(recipient),
        ]);

        let call_args = FunctionCallArgs {
            contract: self.locker_address,
            value: WeiU256::default(),
            input: [LOCKER_UNLOCK_SELECTOR, tail.as_slice()].concat(),
        };

        ext_aurora::call(
            call_args,
            &self.aurora_account,
            NO_DEPOSIT,
            UNLOCK_ERC20_GAS,
        );

        ResultType::Withdraw {
            amount: amount.into(),
            token: token_address,
            recipient: recipient_address,
        }
    }

    #[payable]
    pub fn deploy_bridge_token(&mut self, address: String) -> Promise {
        self.check_not_paused(PAUSE_DEPLOY_TOKEN);
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
        Promise::new(bridge_token_account_id)
            .create_account()
            .transfer(BRIDGE_TOKEN_INIT_BALANCE)
            .add_full_access_key(self.owner_pk.clone())
            .deploy_contract(BRIDGE_TOKEN_BINARY.to_vec())
            .function_call(
                b"new".to_vec(),
                b"{}".to_vec(),
                NO_DEPOSIT,
                BRIDGE_TOKEN_NEW,
            )
    }

    pub fn get_bridge_token_account_id(&self, address: String) -> AccountId {
        let address = address.to_lowercase();
        let _ = validate_eth_address(address.clone());
        assert!(
            self.tokens.contains(&address),
            "BridgeToken with such address does not exist."
        );
        format!("{}.{}", address, env::current_account_id())
    }

    /// Admin method to set metadata with admin/controller access
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
        assert!(self.controller_or_self());
        ext_bridge_token::set_metadata(
            name,
            symbol,
            reference,
            reference_hash,
            decimals,
            icon,
            &self.get_bridge_token_account_id(address),
            env::attached_deposit(),
            env::prepaid_gas() - OUTER_SET_METADATA_GAS,
        )
    }

    /// Factory Controller. Controller has extra privileges inside this contract.
    pub fn controller(&self) -> Option<AccountId> {
        env::storage_read(CONTROLLER_STORAGE_KEY)
            .map(|value| String::from_utf8(value).expect("Invalid controller account id"))
    }

    pub fn set_controller(&mut self, controller: AccountId) {
        assert!(self.controller_or_self());
        assert!(env::is_valid_account_id(controller.as_bytes()));
        env::storage_write(CONTROLLER_STORAGE_KEY, controller.as_bytes());
    }

    pub fn controller_or_self(&self) -> bool {
        let caller = env::predecessor_account_id();
        caller == env::current_account_id()
            || self
                .controller()
                .map(|controller| controller == caller)
                .unwrap_or(false)
    }
}

admin_controlled::impl_admin_controlled!(BridgeTokenFactory, paused);

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, MockedBlockchain};
    use sha3::Digest;

    use super::*;
    use near_sdk::env::sha256;
    use std::convert::TryInto;
    use std::panic;
    use uint::rustc_hex::ToHex;

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

    fn alice() -> AccountId {
        "alice.near".to_string()
    }

    fn aurora() -> AccountId {
        "aurora".to_string()
    }

    fn bridge_token_factory() -> AccountId {
        "bridge".to_string()
    }

    fn token_locker() -> String {
        "6b175474e89094c44da98b954eedeac495271d0f".to_string()
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

    #[test]
    #[should_panic]
    fn test_fail_deploy_bridge_token() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());
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
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());
        set_env!(
            predecessor_account_id: alice(),
            attached_deposit: env::storage_byte_cost() * 1000
        );
        contract.deposit("".to_string(), "1".to_string());
    }

    #[test]
    fn test_deploy_bridge_token() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2,
        );

        contract.deploy_bridge_token(token_locker());
        assert_eq!(
            contract.get_bridge_token_account_id(token_locker()),
            format!("{}.{}", token_locker(), bridge_token_factory())
        );

        let uppercase_address = "0f5Ea0A652E851678Ebf77B69484bFcD31F9459B".to_string();
        contract.deploy_bridge_token(uppercase_address.clone());
        assert_eq!(
            contract.get_bridge_token_account_id(uppercase_address.clone()),
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
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());

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
            contract.finish_withdraw(1_000, token_locker()),
            ResultType::Withdraw {
                amount: 1_000,
                token: address,
                recipient: address
            }
        );
    }

    #[test]
    fn deploy_bridge_token_paused() {
        set_env!(predecessor_account_id: alice());

        // User alice can deploy a new bridge token
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.deploy_bridge_token(ethereum_address_from_id(0));

        // Admin pause deployment of new token
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.set_paused(PAUSE_DEPLOY_TOKEN);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        // Admin can still deploy new tokens after paused
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
    fn only_admin_can_pause() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());

        // Admin can pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
        );
        contract.set_paused(0b1111);

        // Alice can't pause
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
        );

        panic::catch_unwind(move || {
            contract.set_paused(0);
        })
        .unwrap_err();
    }

    #[test]
    fn deposit_paused() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        set_env!(predecessor_account_id: aurora());
        contract.deposit(
            erc20_address.clone(),
            "0".to_string(),
        );

        // Pause deposit
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.set_paused(PAUSE_DEPOSIT);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: aurora(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        // Check it is NOT possible to use deposit while the contract is paused
        panic::catch_unwind(move || {
            contract.deposit(erc20_address, "1".to_string());
        })
        .unwrap_err();
    }

    /// Check after all is paused deposit is not available
    #[test]
    fn all_paused() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: aurora(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        contract.deposit(
            erc20_address.clone(),
            "0".to_string(),
        );

        // Pause everything
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        contract.set_paused(PAUSE_DEPLOY_TOKEN | PAUSE_DEPOSIT);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: aurora(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        // Check it is NOT possible to use deposit while the contract is paused
        panic::catch_unwind(move || {
            contract.deposit(erc20_address, "0".to_string());
        })
        .unwrap_err();
    }

    /// Check after all is paused and unpaused deposit works
    #[test]
    fn no_paused() {
        set_env!(predecessor_account_id: alice());
        let mut contract = BridgeTokenFactory::new(aurora(), token_locker());

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: alice(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );
        let erc20_address = ethereum_address_from_id(0);
        contract.deploy_bridge_token(erc20_address.clone());

        // Check it is possible to use deposit while the contract is NOT paused
        set_env!(predecessor_account_id: aurora());
        contract.deposit(
            erc20_address.clone(),
            "0".to_string(),
        );

        // Pause everything
        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: bridge_token_factory(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        contract.set_paused(PAUSE_DEPLOY_TOKEN | PAUSE_DEPOSIT);
        contract.set_paused(UNPAUSE_ALL);

        set_env!(
            current_account_id: bridge_token_factory(),
            predecessor_account_id: aurora(),
            attached_deposit: BRIDGE_TOKEN_INIT_BALANCE * 2
        );

        // Check the deposit works after pausing and unpausing everything
        contract.deposit(erc20_address, "0".to_string());
    }

    #[test]
    fn check_selector() {
        let mut hasher = sha3::Keccak256::default();
        hasher.update(b"claim(address,uint256)");
        assert_eq!(hasher.finalize()[..4].to_vec(), LOCKER_CLAIM_SELECTOR);

        let mut hasher = sha3::Keccak256::default();
        hasher.update(b"getTokenMetadata(address)");
        assert_eq!(hasher.finalize()[..4].to_vec(), LOCKER_METADATA_SELECTOR);

        let mut hasher = sha3::Keccak256::default();
        hasher.update(b"unlockToken(address,uint256,address)");
        assert_eq!(hasher.finalize()[..4].to_vec(), LOCKER_UNLOCK_SELECTOR);
    }
}
