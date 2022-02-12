use serde_json::json;

use bridge_aurora_token_factory::BridgeTokenFactoryContract;
use near_sdk::json_types::ValidAccountId;
use near_sdk_sim::runtime::GenesisConfig;
use near_sdk_sim::{
    call, deploy, init_simulator, units::to_yocto, view, ContractAccount, ExecutionResult,
    UserAccount,
};

const AURORA: &str = "aurora";
const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "11111474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const SENDER_ADDRESS: &str = "00005474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "alice";

near_sdk_sim::lazy_static_include::lazy_static_include_bytes! {
    TEST_TOKEN_WASM_BYTES => "../res/test_token.wasm",
    TOKEN_WASM_BYTES => "../res/bridge_token.wasm",
    FACTORY_WASM_BYTES => "../res/bridge_aurora_token_factory.wasm",
}

fn setup_token_factory() -> (UserAccount, ContractAccount<BridgeTokenFactoryContract>) {
    let mut config = GenesisConfig::default();
    config.runtime_config.storage_amount_per_byte = 10u128.pow(19);
    let root = init_simulator(Some(config));
    let factory = deploy!(
        contract: BridgeTokenFactoryContract,
        contract_id: FACTORY.to_string(),
        bytes: &FACTORY_WASM_BYTES,
        signer_account: root,
        init_method: new(
            AURORA.to_string(), LOCKER_ADDRESS.to_string()
        )
    );

    (root, factory)
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

fn err_is(result: &ExecutionResult, expected: &str) {
    assert!(!result.is_ok(), "Expected error found {:?}", result);
    let status = format!("{:?}", result.outcome().status);
    assert!(status.contains(expected), "{}", status);
}

#[test]
fn test_eth_token_transfer() {
    let (user, factory) = setup_token_factory();

    let aurora = user.create_user(AURORA.to_string(), to_yocto("100"));
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

    call_json!(aurora, factory_id.deposit({
        "locker_address": LOCKER_ADDRESS.to_string(),
        "token": DAI_ADDRESS.to_string(),
        "sender": SENDER_ADDRESS.to_string(),
        "amount": 1_000,
        "recipient": ALICE.to_string(),
    }))
    .assert_success();

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

#[test]
fn test_deploy_failures() {
    let (user, factory) = setup_token_factory();

    // Fails with not enough deposit.
    err_is(
        &call!(
            user,
            factory.deploy_bridge_token(DAI_ADDRESS.to_string()),
            deposit = to_yocto("0")
        ),
        "Not enough attached deposit to complete bridge token creation",
    );

    // Fails with address is invalid.
    err_is(
        &call!(
            user,
            factory.deploy_bridge_token("not_a_hex".to_string()),
            deposit = to_yocto("0")
        ),
        "address should be a valid hex string.: OddLength",
    );

    // Fails second time because already exists.
    call!(
        user,
        factory.deploy_bridge_token(DAI_ADDRESS.to_string()),
        deposit = to_yocto("35")
    )
    .assert_success();

    err_is(
        &call!(
            user,
            factory.deploy_bridge_token(DAI_ADDRESS.to_string()),
            deposit = to_yocto("35")
        ),
        "BridgeToken contract already exists.",
    );
}
