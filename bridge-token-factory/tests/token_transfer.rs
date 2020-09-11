use borsh::BorshSerialize;
use near_sdk::{AccountId, Balance};
use near_test::test_user::{init_test_runtime, to_yocto, TestRuntime, TxResult};
use near_test::token::TokenContract;
use serde_json::json;

use bridge_token_factory::{validate_eth_address, EthLockedEvent, EthUnlockedEvent, Proof};

const PROVER: &str = "prover";
const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "11111474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const SENDER_ADDRESS: &str = "00005474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "alice";
const TEST_TOKEN: &str = "test-token";

lazy_static::lazy_static! {
    static ref MOCK_PROVER_WASM_BYTES: &'static [u8] = include_bytes!("../../res/mock_prover.wasm").as_ref();
    static ref FACTORY_WASM_BYTES: &'static [u8] = include_bytes!("../../res/bridge_token_factory.wasm").as_ref();
    static ref TEST_TOKEN_WASM_BYTES: &'static [u8] = include_bytes!("../../res/test_token.wasm").as_ref();
}

pub struct BridgeToken {
    pub contract_id: AccountId,
}

impl BridgeToken {
    pub fn get_balance(&self, runtime: &mut TestRuntime, owner: String) -> String {
        TokenContract { contract_id: self.contract_id.clone() }.get_balance(runtime, owner)
    }

    pub fn get_total_supply(&self, runtime: &mut TestRuntime) -> String {
        TokenContract { contract_id: self.contract_id.clone() }.get_total_supply(runtime)
    }

    pub fn mint(
        &self,
        runtime: &mut TestRuntime,
        signer_id: AccountId,
        account_id: AccountId,
        amount: String,
    ) -> TxResult {
        runtime.call(
            signer_id,
            self.contract_id.clone(),
            "mint",
            json!({"amount": amount, "account_id": account_id}),
            0,
        )
    }

    pub fn withdraw(
        &self,
        runtime: &mut TestRuntime,
        signer_id: AccountId,
        amount: String,
        recipient: String,
    ) -> TxResult {
        runtime.call(
            signer_id,
            self.contract_id.clone(),
            "withdraw",
            json!({"amount": amount, "recipient": recipient}),
            0,
        )
    }
}

pub struct BridgeTokenFactory {
    contract_id: AccountId,
}

impl BridgeTokenFactory {
    pub fn new(
        runtime: &mut TestRuntime,
        signer_id: &AccountId,
        contract_id: AccountId,
        prover_account: AccountId,
        locker_address: String,
    ) -> Self {
        let _ = runtime
            .deploy(
                signer_id.clone(),
                contract_id.clone(),
                &FACTORY_WASM_BYTES,
                json!({"prover_account": prover_account, "locker_address": locker_address}),
            )
            .unwrap();
        Self { contract_id }
    }

    pub fn deposit(
        &self,
        runtime: &mut TestRuntime,
        signer_id: &AccountId,
        proof: Proof,
    ) -> TxResult {
        runtime.call_args(
            signer_id.clone(),
            self.contract_id.clone(),
            "deposit",
            proof.try_to_vec().unwrap(),
            to_yocto("1"),
        )
    }

    pub fn deploy_bridge_token(
        &self,
        runtime: &mut TestRuntime,
        signer_id: &AccountId,
        address: String,
        deposit: Balance,
    ) -> TxResult {
        runtime.call(
            signer_id.clone(),
            self.contract_id.clone(),
            "deploy_bridge_token",
            json!({ "address": address }),
            deposit,
        )
    }

    pub fn get_bridge_token_account_id(
        &self,
        runtime: &mut TestRuntime,
        address: String,
    ) -> String {
        runtime
            .view(
                self.contract_id.clone(),
                "get_bridge_token_account_id",
                json!({ "address": address }),
            )
            .as_str()
            .unwrap()
            .to_string()
    }

    pub fn lock(
        &self,
        runtime: &mut TestRuntime,
        signer_id: AccountId,
        token: AccountId,
        amount: Balance,
        recipient: String,
    ) -> TxResult {
        runtime.call(
            signer_id.clone(),
            self.contract_id.clone(),
            "lock",
            json!({"token": token, "amount": amount.to_string(), "recipient": recipient}),
            to_yocto("0.005"),
        )
    }

    pub fn unlock(
        &self,
        runtime: &mut TestRuntime,
        signer_id: AccountId,
        proof: Proof,
    ) -> TxResult {
        runtime.call_args(
            signer_id.clone(),
            self.contract_id.clone(),
            "unlock",
            proof.try_to_vec().unwrap(),
            to_yocto("1"),
        )
    }
}

fn setup_token_factory() -> (TestRuntime, BridgeTokenFactory) {
    let mut runtime = init_test_runtime();
    let root = "root".to_string();
    let _ = runtime
        .deploy(
            root.clone(),
            PROVER.to_string(),
            &MOCK_PROVER_WASM_BYTES,
            json!({}),
        )
        .unwrap();
    let factory = BridgeTokenFactory::new(
        &mut runtime,
        &root,
        FACTORY.to_string(),
        PROVER.to_string(),
        LOCKER_ADDRESS.to_string(),
    );
    (runtime, factory)
}

#[test]
fn test_eth_token_transfer() {
    let (mut runtime, factory) = setup_token_factory();
    let root = "root".to_string();
    runtime.create_user(root.clone(), ALICE.to_string(), to_yocto("1"));

    factory
        .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
        .unwrap();

    let token_account_id =
        factory.get_bridge_token_account_id(&mut runtime, DAI_ADDRESS.to_string());
    assert_eq!(token_account_id, format!("{}.{}", DAI_ADDRESS, FACTORY));

    let token = BridgeToken {
        contract_id: token_account_id,
    };
    assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "0");
    assert_eq!(token.get_total_supply(&mut runtime), "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: 1_000,
        recipient: ALICE.to_string(),
    }
    .to_log_entry_data();
    factory.deposit(&mut runtime, &root, proof).unwrap();

    assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "1000");
    assert_eq!(token.get_total_supply(&mut runtime), "1000");

    token
        .withdraw(
            &mut runtime,
            ALICE.to_string(),
            "100".to_string(),
            SENDER_ADDRESS.to_string(),
        )
        .unwrap();

    assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "900");
    assert_eq!(token.get_total_supply(&mut runtime), "900");
}

#[test]
fn test_near_token_transfer() {
    let (mut runtime, factory) = setup_token_factory();
    let root = "root".to_string();
    let token = TokenContract::new(
        &mut runtime,
        &root,
        &TEST_TOKEN_WASM_BYTES,
        TEST_TOKEN.to_string(),
        &root,
        "1000",
    );
    token
        .inc_allowance(
            &mut runtime,
            &root,
            FACTORY.to_string(),
            to_yocto("100").into(),
        )
        .unwrap();
    factory
        .lock(
            &mut runtime,
            root.clone(),
            TEST_TOKEN.to_string(),
            to_yocto("100"),
            SENDER_ADDRESS.to_string(),
        )
        .unwrap();
    assert_eq!(
        token.get_balance(&mut runtime, root.clone()),
        to_yocto("900").to_string()
    );
    assert_eq!(token.get_total_supply(&mut runtime), to_yocto("1000").to_string());

    let mut proof = Proof::default();
    proof.log_entry_data = EthUnlockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: TEST_TOKEN.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: 50 * 10u128.pow(24),
        recipient: ALICE.to_string(),
    }
    .to_log_entry_data();
    factory.unlock(&mut runtime, root.clone(), proof).unwrap();
    assert_eq!(
        token.get_balance(&mut runtime, ALICE.to_string()),
        to_yocto("50").to_string()
    );
    assert_eq!(token.get_total_supply(&mut runtime), to_yocto("1000").to_string());
}

#[test]
fn test_bridge_token_failures() {
    let (mut runtime, factory) = setup_token_factory();
    let root = "root".to_string();
    runtime.create_user(root.clone(), ALICE.to_string(), to_yocto("1"));
    factory
        .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
        .unwrap();
    let token = BridgeToken {
        contract_id: format!("{}.{}", DAI_ADDRESS, FACTORY),
    };

    // Fail to withdraw because no coins.
    token
        .withdraw(
            &mut runtime,
            root.clone(),
            "100".to_string(),
            SENDER_ADDRESS.to_string(),
        )
        .unwrap_err();

    // Fail to mint because sender is not controller.
    token
        .mint(
            &mut runtime,
            root.clone(),
            ALICE.to_string(),
            "100".to_string(),
        )
        .unwrap_err();
}

/// TODO: instead of just unwrap_err check the specific errors.
#[test]
fn test_deploy_failures() {
    let (mut runtime, factory) = setup_token_factory();
    let root = "root".to_string();

    // Fails with not enough deposit.
    factory
        .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), 0)
        .unwrap_err();

    // Fails with address is invalid.
    factory
        .deploy_bridge_token(
            &mut runtime,
            &root,
            "not_a_hex".to_string(),
            to_yocto("100"),
        )
        .unwrap_err();

    // Fails second time because already exists.
    factory
        .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
        .unwrap();
    factory
        .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
        .unwrap_err();
}
