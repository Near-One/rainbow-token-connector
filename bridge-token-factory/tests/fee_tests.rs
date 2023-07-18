use bridge_token_factory::{validate_eth_address, EthLockedEvent, Proof};
use near_sdk::borsh::{self, BorshSerialize};
use near_sdk::{Balance, ONE_NEAR, ONE_YOCTO};
use serde_json::json;
use tokio::runtime::Runtime;
use workspaces::{network::Sandbox, Account, Contract, Worker};

const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "11111474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const SENDER_ADDRESS: &str = "00005474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "alice.test.near";

const FACTORY_WASM_PATH: &str = "../res/bridge_token_factory.wasm";
const MOCK_PROVER_WASM_PATH: &str = "../res/mock_prover.wasm";

const DEFAULT_DEPOSIT: u128 = ONE_NEAR;

fn create_contract() -> (Account, Contract, Account, Worker<Sandbox>) {
    let rt = Runtime::new().unwrap();

    let worker: Worker<Sandbox> = rt.block_on(workspaces::sandbox()).unwrap();
    let prover_wasm = std::fs::read(MOCK_PROVER_WASM_PATH).unwrap();
    let prover_contract: Contract = rt.block_on(worker.dev_deploy(&prover_wasm)).unwrap();
    let prover_id = prover_contract.id();

    let owner = worker.root_account().unwrap();
    let factory_account = rt
        .block_on(
            owner
                .create_subaccount(FACTORY)
                .initial_balance(200 * ONE_NEAR)
                .transact(),
        )
        .unwrap()
        .into_result()
        .unwrap();

    let factory_wasm = std::fs::read(FACTORY_WASM_PATH).unwrap();
    let factory_contract: Contract = rt
        .block_on(factory_account.deploy(&factory_wasm))
        .unwrap()
        .result;

    let alice = rt
        .block_on(
            owner
                .create_subaccount("alice")
                .initial_balance(200 * ONE_NEAR)
                .transact(),
        )
        .unwrap()
        .into_result()
        .unwrap();

    let _result = rt.block_on(
        factory_account
            .call(factory_contract.id(), "new")
            .args(
                json!({"prover_account": prover_id, "locker_address": LOCKER_ADDRESS.to_string()})
                    .to_string()
                    .into_bytes(),
            )
            .transact(),
    )
    .unwrap();

    let _grant_fee_setter_call = rt
        .block_on(
            factory_account
                .call(factory_contract.id(), "acl_grant_role")
                .args(
                    json!({"role": "FeeSetter".to_string(), "account_id": alice.id()})
                        .to_string()
                        .into_bytes(),
                )
                .transact(),
        )
        .unwrap();
    assert!(
        _grant_fee_setter_call.is_success(),
        "fee setter grant role failed"
    );

    (alice, factory_contract, factory_account, worker)
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

fn remove_quotes(s: &mut String) -> String {
    s.pop();
    s.remove(0);
    s.to_string()
}

fn run_view_function(
    rt: &Runtime,
    contract_id: &String,
    worker: &Worker<Sandbox>,
    function: &str,
    args: serde_json::Value,
) -> String {
    let mut res = std::str::from_utf8(
        &rt.block_on(worker.view(
            &contract_id.parse().unwrap(),
            function,
            args.to_string().into_bytes(),
        ))
        .unwrap()
        .result,
    )
    .unwrap()
    .to_string();
    remove_quotes(&mut res)
}

fn get_fee_amount(
    amount: u128,
    fee_percentage: u128,
    lower_bound: u128,
    upper_bound: u128,
) -> u128 {
    const FEE_DECIMAL_PRECISION: u128 = 100_00_00;
    let mut fee_amount = (amount * fee_percentage) / FEE_DECIMAL_PRECISION;
    if fee_amount < lower_bound {
        fee_amount = lower_bound;
        return fee_amount;
    } else if fee_amount > upper_bound {
        fee_amount = upper_bound;
        return fee_amount;
    } else {
        return fee_amount;
    }
}

#[test]
fn test_token_transfer_with_deposit_and_withdraw_fee() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;
    const WITHDRAW_AMOUNT: u64 = 100;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let deposit_fee_setter_call = &rt
    .block_on(
        alice
            .call(factory.id(), "set_deposit_fee")
            .args(
                json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "400000", "upper_bound": "500", "lower_bound": "100"})
                    .to_string()
                    .into_bytes()
            )
            .max_gas()
            .transact()
    )
    .unwrap();

    assert!(
        deposit_fee_setter_call.is_success(),
        "Fee setter called failed"
    );

    let withdraw_fee_setter_call = &rt
        .block_on(
            alice
                .call(factory.id(), "set_withdraw_fee")
                .args(
                    json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "350000", "upper_bound": "50", "lower_bound": "10"})
                        .to_string()
                        .into_bytes(),
                )
                .max_gas()
                .transact(),
        )
        .unwrap();
    assert!(
        withdraw_fee_setter_call.is_success(),
        "Withdraw Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }
    let deposit_fee_amount =
        get_fee_amount(u128::from(INIT_ALICE_BALANCE), 400000u128, 100u128, 500u128);
    let transfer_amount = INIT_ALICE_BALANCE as u128 - deposit_fee_amount;

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", transfer_amount));

    let token_factory_balance_after_deposit: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string() }),
    );
    assert_eq!(
        token_factory_balance_after_deposit,
        format!("{}", deposit_fee_amount)
    );

    assert!(&rt
        .block_on(
            alice
                .call(&token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : format!("{}", WITHDRAW_AMOUNT),
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .transact(),
        )
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(
        alice_balance,
        format!(
            "{}",
            u128::from(INIT_ALICE_BALANCE) - u128::from(WITHDRAW_AMOUNT) - deposit_fee_amount
        )
    );
    let withdraw_fee_amount =
        get_fee_amount(u128::from(WITHDRAW_AMOUNT), 350000u128, 10u128, 50u128);
    let token_factory_balance_after_withdraw: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string()}),
    );
    assert_eq!(
        format!("{}", deposit_fee_amount + withdraw_fee_amount),
        token_factory_balance_after_withdraw
    );
}

#[test]
fn test_token_deposit_without_fee_bound_and_fee_percentage() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact()
        )
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", INIT_ALICE_BALANCE));

    let token_factory_balance_after_deposit: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string()}),
    );
    assert_eq!(token_factory_balance_after_deposit, format!("{}", 0));
}

#[test]
fn test_token_deposit_with_fee_less_than_lower_bound() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let deposit_fee_setter_call = &rt
    .block_on(
        alice
            .call(factory.id(), "set_deposit_fee")
            .args(
                json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "50000", "upper_bound": "200", "lower_bound": "100"})
                    .to_string()
                    .into_bytes()
            )
            .max_gas()
            .transact()
    )
    .unwrap();
    assert!(
        deposit_fee_setter_call.is_success(),
        "Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }
    let fee_amount = get_fee_amount(u128::from(INIT_ALICE_BALANCE), 50000u128, 100u128, 200u128);
    let transfer_amount = INIT_ALICE_BALANCE as u128 - fee_amount;

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", transfer_amount));

    let token_factory_balance_after_deposit: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string()}),
    );
    assert_eq!(
        token_factory_balance_after_deposit,
        format!("{}", fee_amount)
    );
}

#[test]
fn test_token_deposit_with_fee_more_than_upper_bound() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let deposit_fee_setter_call = &rt
    .block_on(
        alice
            .call(factory.id(), "set_deposit_fee")
            .args(
                json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "400000", "upper_bound": "200", "lower_bound": "100"})
                    .to_string()
                    .into_bytes()
            )
            .max_gas()
            .transact()
    )
    .unwrap();
    assert!(
        deposit_fee_setter_call.is_success(),
        "Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }
    let fee_amount = get_fee_amount(u128::from(INIT_ALICE_BALANCE), 400000u128, 100u128, 200u128);
    let transfer_amount = INIT_ALICE_BALANCE as u128 - fee_amount;

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", transfer_amount));

    let token_factory_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string()}),
    );
    assert_eq!(token_factory_balance, format!("{}", fee_amount));
}

#[test]
fn test_token_deposit_with_fee_in_bound_range() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let deposit_fee_setter_call = &rt
    .block_on(
        alice
            .call(factory.id(), "set_deposit_fee")
            .args(
                json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "400000", "upper_bound": "500", "lower_bound": "100"})
                    .to_string()
                    .into_bytes()
            )
            .max_gas()
            .transact()
    )
    .unwrap();
    assert!(
        deposit_fee_setter_call.is_success(),
        "Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }
    let fee_amount = get_fee_amount(u128::from(INIT_ALICE_BALANCE), 400000u128, 100u128, 500u128);
    let transfer_amount = INIT_ALICE_BALANCE as u128 - fee_amount;

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", transfer_amount));

    let token_factory_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string() }),
    );
    assert_eq!(token_factory_balance, format!("{}", fee_amount));
}

#[test]
fn test_token_withdraw_without_fee_bound_and_fee_percentage() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;
    const WITHDRAW_AMOUNT: u64 = 100;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", INIT_ALICE_BALANCE));

    assert!(&rt
        .block_on(
            alice
                .call(&token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : format!("{}", WITHDRAW_AMOUNT),
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .transact(),
        )
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(
        alice_balance,
        format!(
            "{}",
            u128::from(INIT_ALICE_BALANCE) - u128::from(WITHDRAW_AMOUNT)
        )
    );
    let token_factory_balance_after_withdraw: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string() }),
    );
    assert_eq!(format!("{}", 0), token_factory_balance_after_withdraw);
}

#[test]
fn test_token_withdraw_with_fee_less_than_lower_bound() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;
    const WITHDRAW_AMOUNT: u64 = 100;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let withdraw_fee_setter_call = &rt
        .block_on(
            alice
                .call(factory.id(), "set_withdraw_fee")
                .args(
                    json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "50000", "upper_bound": "20", "lower_bound": "10"})
                        .to_string()
                        .into_bytes(),
                )
                .max_gas()
                .transact(),
        )
        .unwrap();
    assert!(
        withdraw_fee_setter_call.is_success(),
        "Withdraw Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", INIT_ALICE_BALANCE));

    assert!(&rt
        .block_on(
            alice
                .call(&token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : format!("{}", WITHDRAW_AMOUNT),
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .transact(),
        )
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(
        alice_balance,
        format!(
            "{}",
            u128::from(INIT_ALICE_BALANCE) - u128::from(WITHDRAW_AMOUNT)
        )
    );
    let fee_amount = get_fee_amount(u128::from(WITHDRAW_AMOUNT), 50000u128, 10u128, 50u128);
    let token_factory_balance_after_withdraw: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string() }),
    );
    assert_eq!(
        format!("{}", fee_amount),
        token_factory_balance_after_withdraw
    );
}
#[test]
fn test_token_withdraw_with_fee_more_than_upper_bound() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;
    const WITHDRAW_AMOUNT: u64 = 100;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let withdraw_fee_setter_call = &rt
        .block_on(
            alice
                .call(factory.id(), "set_withdraw_fee")
                .args(
                    json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "350000", "upper_bound": "30", "lower_bound": "10"})
                        .to_string()
                        .into_bytes(),
                )
                .max_gas()
                .transact(),
        )
        .unwrap();
    assert!(
        withdraw_fee_setter_call.is_success(),
        "Withdraw Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", INIT_ALICE_BALANCE));

    assert!(&rt
        .block_on(
            alice
                .call(&token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : format!("{}", WITHDRAW_AMOUNT),
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .transact(),
        )
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(
        alice_balance,
        format!(
            "{}",
            u128::from(INIT_ALICE_BALANCE) - u128::from(WITHDRAW_AMOUNT)
        )
    );
    let fee_amount = get_fee_amount(u128::from(WITHDRAW_AMOUNT), 350000u128, 10u128, 30u128);
    let token_factory_balance_after_withdraw: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string() }),
    );
    assert_eq!(
        format!("{}", fee_amount),
        token_factory_balance_after_withdraw
    );
}

#[test]
fn test_token_withdraw_with_fee_in_bound_range() {
    let (alice, factory, _, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;
    const WITHDRAW_AMOUNT: u64 = 100;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let withdraw_fee_setter_call = &rt
        .block_on(
            alice
                .call(factory.id(), "set_withdraw_fee")
                .args(
                    json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "400000", "upper_bound": "50", "lower_bound": "10"})
                        .to_string()
                        .into_bytes(),
                )
                .max_gas()
                .transact(),
        )
        .unwrap();
    assert!(
        withdraw_fee_setter_call.is_success(),
        "Withdraw Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", INIT_ALICE_BALANCE));

    assert!(&rt
        .block_on(
            alice
                .call(&token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : format!("{}", WITHDRAW_AMOUNT),
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .transact(),
        )
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(
        alice_balance,
        format!(
            "{}",
            u128::from(INIT_ALICE_BALANCE) - u128::from(WITHDRAW_AMOUNT)
        )
    );
    let fee_amount = get_fee_amount(u128::from(WITHDRAW_AMOUNT), 400000u128, 10u128, 50u128);
    let token_factory_balance_after_withdraw: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string() }),
    );
    assert_eq!(
        format!("{}", fee_amount),
        token_factory_balance_after_withdraw
    );
}

#[test]
fn test_fee_deposit_claim() {
    let (alice, factory, factory_account, worker) = create_contract();
    let rt = Runtime::new().unwrap();
    const INIT_ALICE_BALANCE: u64 = 1000;
    const WITHDRAW_AMOUNT: u64 = 100;

    assert!(&rt
        .block_on(
            alice
                .call(factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(
                    json!({"address": DAI_ADDRESS.to_string()})
                        .to_string()
                        .into_bytes()
                )
                .max_gas()
                .transact()
        )
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &rt,
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    );

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    assert_eq!(alice_balance, "0");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "0");

    let _grant_fee_claimer_role_call = rt
        .block_on(
            factory_account
                .call(factory.id(), "acl_grant_role")
                .args(
                    json!({"role": "FeeClaimer".to_string(), "account_id": alice.id()})
                        .to_string()
                        .into_bytes(),
                )
                .transact(),
        )
        .unwrap();
    assert!(
        _grant_fee_claimer_role_call.is_success(),
        "fee setter grant role failed"
    );

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: Balance::from(INIT_ALICE_BALANCE),
        recipient: ALICE.parse().unwrap(),
    }
    .to_log_entry_data();

    let deposit_fee_setter_call = &rt
    .block_on(
        alice
            .call(factory.id(), "set_deposit_fee")
            .args(
                json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "400000", "upper_bound": "500", "lower_bound": "100"})
                    .to_string()
                    .into_bytes()
            )
            .max_gas()
            .transact()
    )
    .unwrap();
    assert!(
        deposit_fee_setter_call.is_success(),
        "Fee setter called failed"
    );

    let withdraw_fee_setter_call = &rt
        .block_on(
            alice
                .call(factory.id(), "set_withdraw_fee")
                .args(
                    json!({"token": DAI_ADDRESS.to_string(), "fee_percentage": "350000", "upper_bound": "50", "lower_bound": "10"})
                        .to_string()
                        .into_bytes(),
                )
                .max_gas()
                .transact(),
        )
        .unwrap();
    assert!(
        withdraw_fee_setter_call.is_success(),
        "Withdraw Fee setter called failed"
    );

    let deposit_call = &rt
        .block_on(
            alice
                .call(factory.id(), "deposit")
                .deposit(DEFAULT_DEPOSIT)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        )
        .unwrap();
    if deposit_call.is_failure() {
        println!("\n\n\n Deposit error {:?}\n\n", deposit_call.failures());
    }
    let deposit_fee_amount =
        get_fee_amount(u128::from(INIT_ALICE_BALANCE), 400000u128, 100u128, 500u128);
    let transfer_amount = INIT_ALICE_BALANCE as u128 - deposit_fee_amount;

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(alice_balance, format!("{}", transfer_amount));

    let token_factory_balance_after_deposit: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string() }),
    );
    assert_eq!(
        token_factory_balance_after_deposit,
        format!("{}", deposit_fee_amount)
    );

    assert!(&rt
        .block_on(
            alice
                .call(&token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : format!("{}", WITHDRAW_AMOUNT),
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .transact(),
        )
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    assert_eq!(
        alice_balance,
        format!(
            "{}",
            u128::from(INIT_ALICE_BALANCE) - u128::from(WITHDRAW_AMOUNT) - deposit_fee_amount
        )
    );
    let withdraw_fee_amount =
        get_fee_amount(u128::from(WITHDRAW_AMOUNT), 350000u128, 10u128, 50u128);
    let token_factory_balance_after_withdraw: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string()}),
    );
    assert_eq!(
        format!("{}", deposit_fee_amount + withdraw_fee_amount),
        token_factory_balance_after_withdraw
    );

    let alice_balance_before_claim: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );

    let claim_fee_call = &rt
        .block_on(
            alice
                .call(factory.id(), "claim_fee")
                .deposit(ONE_YOCTO)
                .args(
                    json!({"token": token_account_id, "amount": 50})
                        .to_string()
                        .into_bytes(),
                )
                .max_gas()
                .transact(),
        )
        .unwrap();
    assert!(claim_fee_call.is_success(), "Claim Fee call failed");

    let token_factory_balance_after_claim: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": factory.id().to_string()}),
    );

    let alice_balance_after_claim: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    );
    let alice_bal_before_claim: u128 = alice_balance_before_claim.parse().unwrap();
    let token_factory_balance_before_claim: u128 =
        token_factory_balance_after_withdraw.parse().unwrap();
    assert_eq!(
        format!("{}", token_factory_balance_before_claim - 50),
        token_factory_balance_after_claim,
        "Token Factory balance didn't matched before and after fee is claimed"
    );
    assert_eq!(
        format!("{}", alice_bal_before_claim + 50),
        alice_balance_after_claim,
        "Before-After claim balance of alice not matched"
    );
}
