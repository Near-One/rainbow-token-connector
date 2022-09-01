use bridge_token_factory::{validate_eth_address, EthLockedEvent, Proof};
use near_sdk::borsh::{self, BorshSerialize};
use near_sdk::{AccountId, ONE_NEAR, ONE_YOCTO};
use serde_json::json;
use tokio::runtime::Runtime;
use workspaces::prelude::*;
use workspaces::result::CallExecutionDetails;
use workspaces::{network::Sandbox, Account, Contract, Worker};

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
                .initial_balance(200 * ONE_NEAR)
                .transact(),
        )
        .unwrap()
        .into_result()
        .unwrap();

    let factory_wasm = std::fs::read(FACTORY_WASM_PATH).unwrap();
    let factory_contract: Contract = rt
        .block_on(factory_account.deploy(&worker, &factory_wasm))
        .unwrap()
        .result;

    let alice = rt
        .block_on(
            owner
                .create_subaccount(&worker, "alice")
                .initial_balance(200 * ONE_NEAR)
                .transact(),
        )
        .unwrap()
        .into_result()
        .unwrap();

    rt.block_on(
        alice
            .call(&worker, factory_contract.id(), "new")
            .args(
                json!({"prover_account": prover_id, "locker_address": LOCKER_ADDRESS.to_string()})
                    .to_string()
                    .into_bytes(),
            )
            .transact(),
    )
    .unwrap();

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

fn assert_error(result: &Result<CallExecutionDetails, anyhow::Error>, expected: &str) {
    let status = match result {
        Ok(result) => {
            assert!(!result.is_success(), "Expected error found {:?}", result);
            format!("{:?}", result.outcome())
        }
        Err(err) => {
            format!("{:?}", err)
        }
    };

    assert!(status.contains(expected), "{}", status);
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

#[test]
fn test_eth_token_transfer() {
    let (user, factory, worker) = create_contract();
    let rt = Runtime::new().unwrap();

    assert!(&rt
        .block_on(
            user.call(&worker, factory.id(), "deploy_bridge_token")
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
        json!({"account_id": user.id().to_string()}),
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
        amount: 1_000,
        recipient: user.id().to_string().parse().unwrap(),
    }
    .to_log_entry_data();

    assert!(&rt
        .block_on(
            user.call(&worker, factory.id(), "deposit")
                .deposit(50 * ONE_NEAR)
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
        json!({"account_id": user.id().to_string()}),
    );
    assert_eq!(alice_balance, "1000");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "1000");

    assert!(&rt
        .block_on(
            user.call(&worker, &token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : "100",
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
        json!({"account_id": user.id().to_string()}),
    );
    assert_eq!(alice_balance, "900");

    let total_supply: String = run_view_function(
        &rt,
        &token_account_id,
        &worker,
        "ft_total_supply",
        json!({}),
    );
    assert_eq!(total_supply, "900");
}

#[test]
fn test_with_invalid_proof() {
    let (user, factory, worker) = create_contract();
    let rt = Runtime::new().unwrap();

    assert!(&rt
        .block_on(
            user.call(&worker, factory.id(), "deploy_bridge_token")
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

    assert_error(
        &rt.block_on(
            user.call(&worker, factory.id(), "deposit")
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        ),
        "Failed to verify the proof",
    );

    // Convert the proof in a valid proof that is going to be accepted by the mock_prover.
    proof.proof.clear();

    // This deposit event must succeed. Notice that previously a similar deposit
    // was made, but it failed because it had an invalid proof, so this one should succeed.
    assert!(&rt
        .block_on(
            user.call(&worker, factory.id(), "deposit")
                .deposit(50 * ONE_NEAR)
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact()
        )
        .unwrap()
        .is_success());

    // This deposit event must fail since same deposit event can't be reused.
    // Previous call to deposit with the same event was successful.
    assert_error(
        &rt.block_on(
            user.call(&worker, factory.id(), "deposit")
                .max_gas()
                .args(proof.try_to_vec().unwrap())
                .transact(),
        ),
        "Event cannot be reused for depositing.",
    );
}

#[test]
fn test_bridge_token_failures() {
    let (user, factory, worker) = create_contract();
    let rt = Runtime::new().unwrap();

    assert!(&rt
        .block_on(
            user.call(&worker, factory.id(), "deploy_bridge_token")
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

    let token_account_id = format!("{}.{}", DAI_ADDRESS, factory.id());

    // Fail to withdraw because the account is not registered (and have no coins)
    assert_error(
        &rt.block_on(
            user.call(&worker, &token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .deposit(ONE_YOCTO)
                .args(
                    json!({
                        "amount" : "100",
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .transact(),
        ),
        " is not registered",
    );

    // Register the account
    let account_id: Option<AccountId> = None;
    let registration_only: Option<bool> = None;

    assert!(&rt
        .block_on(
            user.call(
                &worker,
                &token_account_id.parse().unwrap(),
                "storage_deposit"
            )
            .max_gas()
            .args(
                json!({
                    "account_id": account_id,
                    "registration_only": registration_only
                })
                .to_string()
                .into_bytes()
            )
            .deposit(ONE_NEAR)
            .transact()
        )
        .unwrap()
        .is_success());

    // Fail to withdraw because the account has no enough balance
    assert_error(
        &rt.block_on(
            user.call(&worker, &token_account_id.parse().unwrap(), "withdraw")
                .max_gas()
                .args(
                    json!({
                        "amount" : "100",
                        "recipient" : SENDER_ADDRESS.to_string()
                    })
                    .to_string()
                    .into_bytes(),
                )
                .deposit(ONE_YOCTO)
                .transact(),
        ),
        "The account doesn't have enough balance",
    );

    let other_user = rt
        .block_on(
            user.create_subaccount(&worker, "bob")
                .initial_balance(50 * ONE_NEAR)
                .transact(),
        )
        .unwrap()
        .into_result()
        .unwrap();

    // Fail to mint because the caller is not the controller
    assert_error(
        &rt.block_on(
            other_user
                .call(&worker, &token_account_id.parse().unwrap(), "mint")
                .max_gas()
                .args(
                    json!({
                        "account_id" : ALICE.to_string(),
                        "amount" : "100"
                    })
                    .to_string()
                    .into_bytes(),
                )
                .deposit(ONE_YOCTO)
                .transact(),
        ),
        "Only controller can call mint",
    );
}

#[test]
fn test_deploy_failures() {
    let (user, factory, worker) = create_contract();
    let rt = Runtime::new().unwrap();

    // Fails with not enough deposit.
    assert_error(
        &rt.block_on(
            user.call(&worker, factory.id(), "deploy_bridge_token")
                .deposit(0)
                .args(json!({ "address": DAI_ADDRESS }).to_string().into_bytes())
                .max_gas()
                .transact(),
        ),
        "Not enough attached deposit to complete bridge token creation",
    );

    // Fails with address is invalid.
    assert_error(
        &rt.block_on(
            user.call(&worker, factory.id(), "deploy_bridge_token")
                .deposit(0)
                .args(json!({"address": "not_a_hex"}).to_string().into_bytes())
                .max_gas()
                .transact(),
        ),
        "address should be a valid hex string.: OddLength",
    );

    // Fails second time because already exists.
    assert!(&rt
        .block_on(
            user.call(&worker, factory.id(), "deploy_bridge_token")
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

    assert_error(
        &rt.block_on(
            user.call(&worker, factory.id(), "deploy_bridge_token")
                .deposit(35 * ONE_NEAR)
                .args(json!({ "address": DAI_ADDRESS }).to_string().into_bytes())
                .max_gas()
                .transact(),
        ),
        "BridgeToken contract already exists.",
    );
}
