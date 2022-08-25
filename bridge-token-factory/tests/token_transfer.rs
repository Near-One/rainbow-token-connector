use near_sdk::AccountId;
use near_sdk::borsh::{self, BorshSerialize};
use serde_json::json;
use bridge_token_factory::{validate_eth_address, EthLockedEvent, Proof};
use near_sdk::json_types::ValidAccountId;
use workspaces::prelude::*;
use workspaces::{network::Sandbox, Account, Contract, Worker};
use workspaces::result::CallExecutionDetails;
use near_units::*;
use tokio::runtime::Runtime;

const PROVER: &str = "prover";
const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "11111474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const SENDER_ADDRESS: &str = "00005474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "alice";

const FACTORY_WASM_PATH: &str = "../res/bridge_token_factory.wasm";
const MOCK_PROVER_WASM_PATH: &str = "../res/mock_prover.wasm";

fn create_contract() -> (Account, Contract, Worker<Sandbox>) {
    let rt = Runtime::new().unwrap();

    let worker: Worker<Sandbox> = rt.block_on(workspaces::sandbox()).unwrap();
    let prover_wasm = std::fs::read(MOCK_PROVER_WASM_PATH).unwrap();
    let prover_contract: Contract = rt.block_on(worker.dev_deploy(&prover_wasm)).unwrap();
    let prover_id = prover_contract.id();

    let owner = worker.root_account().unwrap();
    let factory_account = rt
        .block_on(
            owner
                .create_subaccount(&worker, FACTORY)
                .initial_balance(parse_near!("200 N"))
                .transact(),
        )
        .unwrap()
        .into_result()
        .unwrap();

    let factory_wasm = std::fs::read(FACTORY_WASM_PATH).unwrap();
    let factory_contract: Contract = rt.block_on(factory_account.deploy(&worker, &factory_wasm)).unwrap().result;

    let alice = rt
        .block_on(
            owner
                .create_subaccount(&worker, "alice")
                .initial_balance(parse_near!("200 N"))
                .transact(),
        )
        .unwrap()
        .into_result()
        .unwrap();

    rt.block_on(alice
        .call(&worker, factory_contract.id(), "new")
        .args(json!({"prover_account": prover_id, "locker_address": LOCKER_ADDRESS.to_string()}).to_string().into_bytes())
        .transact()).unwrap();

    (alice, factory_contract, worker)
}

#[derive(BorshSerialize)]
struct AugmentedProof {
    proof: Proof,
    skip_call: bool,
}

impl From<Proof> for AugmentedProof {
    fn from(proof: Proof) -> Self {
        Self {
            proof,
            skip_call: false,
        }
    }
}

#[macro_export]
macro_rules! call_json {
    ($signer:expr, $contract:ident, $method:ident, $arg:tt, $gas:expr, $deposit:expr) => {
        $signer.call(
            $contract.clone(),
            stringify!($method),
            json!($arg).to_string().into_bytes().as_ref(),
            $gas,
            $deposit,
        )
    };
    ($signer:expr, $contract:ident.$method:ident($arg:tt), $gas:expr, $deposit:expr) => {
        call_json!($signer, $contract, $method, $arg, $gas, $deposit)
    };
    ($signer:expr, $contract:ident.$method:ident($arg:tt)) => {
        call_json!(
            $signer,
            $contract,
            $method,
            $arg,
            near_sdk_sim::DEFAULT_GAS,
            near_sdk_sim::STORAGE_AMOUNT
        )
    };
    ($signer:expr, $contract:ident.$method:ident($arg:tt), deposit=$deposit:expr) => {
        call_json!(
            $signer,
            $contract,
            $method,
            $arg,
            near_sdk_sim::DEFAULT_GAS,
            $deposit
        )
    };
}

#[macro_export]
macro_rules! call_borsh {
    ($signer:expr, $contract:ident, $method:ident, $arg:expr, $gas:expr, $deposit:expr) => {
        $signer.call(
            $contract.clone(),
            stringify!($method),
            &$arg.try_to_vec().unwrap(),
            $gas,
            $deposit,
        )
    };
    ($signer:expr, $contract:ident.$method:ident($arg:expr), $gas:expr, $deposit:expr) => {
        call_borsh!($signer, $contract, $method, $arg, $gas, $deposit)
    };
    ($signer:expr, $contract:ident.$method:ident($arg:expr)) => {
        call_borsh!(
            $signer,
            $contract,
            $method,
            $arg,
            near_sdk_sim::DEFAULT_GAS,
            near_sdk_sim::STORAGE_AMOUNT
        )
    };
    ($signer:expr, $contract:ident.$method:ident($arg:expr), deposit=$deposit:expr) => {
        call_borsh!(
            $signer,
            $contract,
            $method,
            $arg,
            near_sdk_sim::DEFAULT_GAS,
            $deposit
        )
    };
}

fn err_is(result: &Result<CallExecutionDetails, anyhow::Error>, expected: &str) {
    let status = match result {
        Ok(result) => {
            assert!(!result.is_success(), "Expected error found {:?}", result);
            format!("{:?}", result.outcome())
        },
        Err(err) => {
            format!("{:?}", err)
        }
    };

    assert!(status.contains(expected), "{}", status);
}

/*
#[test]
fn test_eth_token_transfer() {
    let (user, factory) = setup_token_factory();

    let alice = user.create_user(ALICE.to_string(), to_yocto("100"));
    let factory_id = FACTORY.to_string();

    call!(
        user,
        factory.deploy_bridge_token(DAI_ADDRESS.to_string()),
        deposit = to_yocto("35")
    )
    .assert_success();

    let token_account_id: String =
        view!(factory.get_bridge_token_account_id(DAI_ADDRESS.to_string())).unwrap_json();
    assert_eq!(token_account_id, format!("{}.{}", DAI_ADDRESS, FACTORY));

    let alice_balance: String =
        call_json!(user, token_account_id.ft_balance_of({"account_id": ALICE.to_string()}))
            .unwrap_json();
    assert_eq!(alice_balance, "0");

    let total_supply: String = call_json!(user, token_account_id.ft_total_supply({})).unwrap_json();
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: 1_000,
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    call_borsh!(user, factory_id.deposit(proof)).assert_success();

    let alice_balance: String =
        call_json!(user, token_account_id.ft_balance_of({"account_id": ALICE.to_string()}))
            .unwrap_json();
    assert_eq!(alice_balance, "1000");

    let total_supply: String = call_json!(user, token_account_id.ft_total_supply({})).unwrap_json();
    assert_eq!(total_supply, "1000");

    call_json!(alice, token_account_id.withdraw({
                "amount" : "100",
                "recipient" : SENDER_ADDRESS.to_string()}), deposit=1)
    .assert_success();

    let alice_balance: String =
        call_json!(user, token_account_id.ft_balance_of({"account_id": ALICE.to_string()}))
            .unwrap_json();
    assert_eq!(alice_balance, "900");

    let total_supply: String = call_json!(user, token_account_id.ft_total_supply({})).unwrap_json();
    assert_eq!(total_supply, "900");
}

#[test]
fn test_with_invalid_proof() {
    let (user, factory) = setup_token_factory();

    call!(
        user,
        factory.deploy_bridge_token(DAI_ADDRESS.to_string()),
        deposit = to_yocto("35")
    )
    .assert_success();

    let token_account_id: String = call!(
        user,
        factory.get_bridge_token_account_id(DAI_ADDRESS.to_string())
    )
    .unwrap_json();
    assert_eq!(token_account_id, format!("{}.{}", DAI_ADDRESS, FACTORY));

    let mut proof = Proof::default();

    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: 1_000,
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    // This is an invalid proof that will not pass proof validation
    // since mock_prover will only accept empty proofs.
    proof.proof = vec![vec![]];

    let factory_id = FACTORY.to_string();
    err_is(
        &call_borsh!(user, factory_id.deposit(proof)),
        "Failed to verify the proof",
    );

    // Convert the proof in a valid proof that is going to be accepted by the mock_prover.
    proof.proof.clear();

    // This deposit event must succeed. Notice that previously a similar deposit
    // was made, but it failed because it had an invalid proof, so this one should succeed.
    call_borsh!(user, factory_id.deposit(proof)).assert_success();

    // This deposit event must fail since same deposit event can't be reused.
    // Previous call to deposit with the same event was successful.
    err_is(
        &call_borsh!(user, factory_id.deposit(proof)),
        "Event cannot be reused for depositing.",
    );
}

#[test]
fn test_bridge_token_failures() {
    let (user, factory) = setup_token_factory();

    call!(
        user,
        factory.deploy_bridge_token(DAI_ADDRESS.to_string()),
        deposit = to_yocto("35")
    )
    .assert_success();

    let token_account_id = format!("{}.{}", DAI_ADDRESS, FACTORY);

    // Fail to withdraw because the account is not registered (and have no coins)
    err_is(
        &call_json!(user, token_account_id.withdraw({
                "amount" : "100",
                "recipient" : SENDER_ADDRESS.to_string()}), deposit=1),
        "The account is not registered",
    );

    // Register the account
    let account_id: Option<ValidAccountId> = None;
    let registration_only: Option<bool> = None;
    call_json!(user, token_account_id.storage_deposit({
        "account_id": account_id,
        "registration_only": registration_only,
    }))
    .assert_success();

    // Fail to withdraw because the account has no enough balance
    err_is(
        &call_json!(user, token_account_id.withdraw({
                "amount" : "100",
                "recipient" : SENDER_ADDRESS.to_string()}), deposit=1),
        "The account doesn't have enough balance",
    );

    // Fail to mint because the caller is not the controller
    let other_user = user.create_user(ALICE.to_string(), to_yocto("1"));
    err_is(
        &call_json!(other_user, token_account_id.mint({
                "account_id" : ALICE.to_string(),
                "amount" : "100"}), deposit=1),
        "Only controller can call mint",
    );
}
*/

#[test]
fn test_deploy_failures() {
    let (user, factory, worker) = create_contract();
    let rt = Runtime::new().unwrap();

    // Fails with not enough deposit.
    err_is(&rt.block_on(user.call(&worker, factory.id(), "deploy_bridge_token")
        .deposit(0)
        .args(json!({"address": DAI_ADDRESS}).to_string().into_bytes())
        .max_gas()
        .transact()),
        "Not enough attached deposit to complete bridge token creation",
    );

    // Fails with address is invalid.
    err_is(
        &rt.block_on(user.call(&worker, factory.id(), "deploy_bridge_token")
            .deposit(0)
            .args(json!({"address": "not_a_hex"}).to_string().into_bytes())
            .max_gas()
            .transact()),
        "address should be a valid hex string.: OddLength",
    );

    println!("{}.{}", DAI_ADDRESS.to_string(), factory.id());
    let new_account_id: near_sdk::AccountId = format!("{}.{}", DAI_ADDRESS.to_string(), factory.id()).parse().unwrap();

    // Fails second time because already exists.
    assert!(&rt.block_on(user.call(&worker, factory.id(), "deploy_bridge_token")
        .deposit(parse_near!("35 N"))
        .args(json!({"address": DAI_ADDRESS.to_string()}).to_string().into_bytes())
        .max_gas()
        .transact()).unwrap().is_success());

    err_is(&rt.block_on(user.call(&worker, factory.id(), "deploy_bridge_token")
        .deposit(parse_near!("35 N"))
        .args(json!({"address": DAI_ADDRESS}).to_string().into_bytes())
        .max_gas()
        .transact()),
        "BridgeToken contract already exists.",
    );
}