use bridge_token_factory::{validate_eth_address, EthLockedEvent, Proof};
use near_sdk::borsh::{self, BorshSerialize};
use near_sdk::{AccountId, Balance, ONE_NEAR, ONE_YOCTO};
use near_workspaces::{network::Sandbox, result::ExecutionFinalResult, Account, Contract, Worker};
use serde_json::json;

const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "11111474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const SENDER_ADDRESS: &str = "00005474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "alice.test.near";

const FACTORY_WASM_PATH: &str = "../res/bridge_token_factory.wasm";
const FACTORY_WASM_PATH_V_0_1_6: &str = "res/bridge_token_factory_v0.1.6.wasm";
const BRIDGE_TOKEN_WASM_PATH: &str = "../res/bridge_token.wasm";
const MOCK_PROVER_WASM_PATH: &str = "../res/mock_prover.wasm";

const DEFAULT_DEPOSIT: u128 = ONE_NEAR;

async fn create_contract(factory_wasm_path: &str) -> (Account, Contract, Worker<Sandbox>) {
    let worker: Worker<Sandbox> = near_workspaces::sandbox().await.unwrap();
    let prover_wasm = std::fs::read(MOCK_PROVER_WASM_PATH).unwrap();
    let prover_contract: Contract = worker.dev_deploy(&prover_wasm).await.unwrap();
    let prover_id = prover_contract.id();

    let owner = worker.root_account().unwrap();
    let factory_account = owner
        .create_subaccount(FACTORY)
        .initial_balance(200 * ONE_NEAR)
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();

    let factory_wasm = std::fs::read(factory_wasm_path).unwrap();
    let factory_contract: Contract = factory_account.deploy(&factory_wasm).await.unwrap().result;

    let alice = owner
        .create_subaccount("alice")
        .initial_balance(200 * ONE_NEAR)
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();

    let _result = factory_account
        .call(factory_contract.id(), "new")
        .args(
            json!({"prover_account": prover_id, "locker_address": LOCKER_ADDRESS.to_string()})
                .to_string()
                .into_bytes(),
        )
        .transact()
        .await
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

fn assert_error(
    result: &Result<ExecutionFinalResult, near_workspaces::error::Error>,
    expected: &str,
) {
    let status = match result {
        Ok(result) => {
            assert!(result.is_failure(), "Expected error found {:?}", result);
            format!("{:?}", result.clone().into_result().err())
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

async fn run_view_function(
    contract_id: &String,
    worker: &Worker<Sandbox>,
    function: &str,
    args: serde_json::Value,
) -> String {
    let mut res = std::str::from_utf8(
        &worker
            .view(&contract_id.parse().unwrap(), function)
            .args_json(args)
            .await
            .unwrap()
            .result,
    )
    .unwrap()
    .to_string();
    remove_quotes(&mut res)
}

#[tokio::test]
async fn test_eth_token_transfer() {
    let (alice, factory, worker) = create_contract(FACTORY_WASM_PATH).await;
    const INIT_ALICE_BALANCE: u64 = 1000;
    const WITHDRAW_AMOUNT: u64 = 100;

    assert!(alice
        .call(factory.id(), "deploy_bridge_token")
        .deposit(35 * ONE_NEAR)
        .args(
            json!({"address": DAI_ADDRESS.to_string()})
                .to_string()
                .into_bytes()
        )
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    )
    .await;

    assert_eq!(
        token_account_id,
        format!("{}.{}", DAI_ADDRESS, factory.id())
    );

    let alice_balance: String = run_view_function(
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    )
    .await;

    assert_eq!(alice_balance, "0");

    let total_supply: String =
        run_view_function(&token_account_id, &worker, "ft_total_supply", json!({})).await;
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

    assert!(alice
        .call(factory.id(), "deposit")
        .deposit(DEFAULT_DEPOSIT)
        .max_gas()
        .args(proof.try_to_vec().unwrap())
        .transact()
        .await
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    )
    .await;
    assert_eq!(alice_balance, format!("{}", INIT_ALICE_BALANCE));

    let total_supply: String =
        run_view_function(&token_account_id, &worker, "ft_total_supply", json!({})).await;
    assert_eq!(total_supply, format!("{}", INIT_ALICE_BALANCE));

    assert!(alice
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
        .transact()
        .await
        .unwrap()
        .is_success());

    let alice_balance: String = run_view_function(
        &token_account_id,
        &worker,
        "ft_balance_of",
        json!({ "account_id": ALICE }),
    )
    .await;
    assert_eq!(
        alice_balance,
        format!("{}", INIT_ALICE_BALANCE - WITHDRAW_AMOUNT)
    );

    let total_supply: String =
        run_view_function(&token_account_id, &worker, "ft_total_supply", json!({})).await;
    assert_eq!(
        total_supply,
        format!("{}", INIT_ALICE_BALANCE - WITHDRAW_AMOUNT)
    );
}

#[tokio::test]
async fn test_with_invalid_proof() {
    let (user, factory, worker) = create_contract(FACTORY_WASM_PATH).await;

    assert!(user
        .call(factory.id(), "deploy_bridge_token")
        .deposit(35 * ONE_NEAR)
        .args(
            json!({"address": DAI_ADDRESS.to_string()})
                .to_string()
                .into_bytes()
        )
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    let token_account_id: String = run_view_function(
        &factory.id().to_string(),
        &worker,
        "get_bridge_token_account_id",
        json!({"address": DAI_ADDRESS.to_string()}),
    )
    .await;

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
        &user
            .call(factory.id(), "deposit")
            .max_gas()
            .args(proof.try_to_vec().unwrap())
            .transact()
            .await,
        "Failed to verify the proof",
    );

    // Convert the proof in a valid proof that is going to be accepted by the mock_prover.
    proof.proof.clear();

    // This deposit event must succeed. Notice that previously a similar deposit
    // was made, but it failed because it had an invalid proof, so this one should succeed.
    assert!(user
        .call(factory.id(), "deposit")
        .max_gas()
        .deposit(DEFAULT_DEPOSIT)
        .args(proof.try_to_vec().unwrap())
        .transact()
        .await
        .unwrap()
        .is_success());

    // This deposit event must fail since same deposit event can't be reused.
    // Previous call to deposit with the same event was successful.
    assert_error(
        &user
            .call(factory.id(), "deposit")
            .max_gas()
            .args(proof.try_to_vec().unwrap())
            .transact()
            .await,
        "Event cannot be reused for depositing.",
    );
}

#[tokio::test]
async fn test_bridge_token_failures() {
    let (user, factory, _worker) = create_contract(FACTORY_WASM_PATH).await;

    assert!(user
        .call(factory.id(), "deploy_bridge_token")
        .deposit(35 * ONE_NEAR)
        .args(
            json!({"address": DAI_ADDRESS.to_string()})
                .to_string()
                .into_bytes()
        )
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    let token_account_id = format!("{}.{}", DAI_ADDRESS, factory.id());

    // Fail to withdraw because the account is not registered (and have no coins)
    assert_error(
        &user
            .call(&token_account_id.parse().unwrap(), "withdraw")
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
            .transact()
            .await,
        " is not registered",
    );

    // Register the account
    let account_id: Option<AccountId> = None;
    let registration_only: Option<bool> = None;

    assert!(user
        .call(&token_account_id.parse().unwrap(), "storage_deposit")
        .max_gas()
        .args(
            json!({
                "account_id": account_id,
                "registration_only": registration_only
            })
            .to_string()
            .into_bytes()
        )
        .deposit(DEFAULT_DEPOSIT)
        .transact()
        .await
        .unwrap()
        .is_success());

    // Fail to withdraw because the account has no enough balance
    assert_error(
        &user
            .call(&token_account_id.parse().unwrap(), "withdraw")
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
            .transact()
            .await,
        "The account doesn't have enough balance",
    );

    let other_user = user
        .create_subaccount("bob")
        .initial_balance(50 * ONE_NEAR)
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();

    // Fail to mint because the caller is not the controller
    assert_error(
        &other_user
            .call(&token_account_id.parse().unwrap(), "mint")
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
            .transact()
            .await,
        "Only controller can call mint",
    );
}

#[tokio::test]
async fn test_deploy_failures() {
    let (user, factory, _worker) = create_contract(FACTORY_WASM_PATH).await;

    // Fails with not enough deposit.
    assert_error(
        &user
            .call(factory.id(), "deploy_bridge_token")
            .deposit(0)
            .args(json!({ "address": DAI_ADDRESS }).to_string().into_bytes())
            .max_gas()
            .transact()
            .await,
        "Not enough attached deposit to complete bridge token creation",
    );

    // Fails with address is invalid.
    assert_error(
        &user
            .call(factory.id(), "deploy_bridge_token")
            .deposit(0)
            .args(json!({"address": "not_a_hex"}).to_string().into_bytes())
            .max_gas()
            .transact()
            .await,
        "address should be a valid hex string.: OddLength",
    );

    // Fails second time because already exists.
    assert!(user
        .call(factory.id(), "deploy_bridge_token")
        .deposit(35 * ONE_NEAR)
        .args(
            json!({"address": DAI_ADDRESS.to_string()})
                .to_string()
                .into_bytes()
        )
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    assert_error(
        &user
            .call(factory.id(), "deploy_bridge_token")
            .deposit(35 * ONE_NEAR)
            .args(json!({ "address": DAI_ADDRESS }).to_string().into_bytes())
            .max_gas()
            .transact()
            .await,
        "BridgeToken contract already exists.",
    );
}

#[tokio::test]
async fn test_upgrade() {
    let (alice, factory, worker) = create_contract(FACTORY_WASM_PATH_V_0_1_6).await;

    let token_account = Account::from_secret_key(
        format!("{}.{}", DAI_ADDRESS, factory.id()).parse().unwrap(),
        factory.as_account().secret_key().clone(),
        &worker,
    );

    assert!(alice
        .call(factory.id(), "deploy_bridge_token")
        .deposit(35 * ONE_NEAR)
        .args(
            json!({"address": DAI_ADDRESS.to_string()})
                .to_string()
                .into_bytes()
        )
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    let token_account_id: String = factory
        .view("get_bridge_token_account_id")
        .args_json(json!({"address": DAI_ADDRESS.to_string()}))
        .await
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(token_account_id, token_account.id().to_string());

    // Deploy new version
    let factory = factory
        .as_account()
        .deploy(&(std::fs::read(FACTORY_WASM_PATH).unwrap()))
        .await
        .unwrap()
        .result;

    let token_account_id: String = factory
        .view("get_bridge_token_account_id")
        .args_json(json!({"address": DAI_ADDRESS.to_string()}))
        .await
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(token_account_id, token_account.id().to_string());

    // Verify the factory version
    let factory_version: String = factory.view("version").await.unwrap().json().unwrap();
    assert_eq!(factory_version, "0.2.1");

    // Set alice as super admin
    let result = factory
        .call("acl_init_super_admin")
        .args_json(json!({
           "account_id": alice.id().to_string()
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();

    let result: bool = result.json().unwrap();
    assert!(result);

    // Grant alice the `TokenUpgradableManager` role
    let result = alice
        .call(factory.id(), "acl_grant_role")
        .args(
            json!({
               "role": "TokenUpgradableManager",
               "account_id": alice.id().to_string()
            })
            .to_string()
            .into_bytes(),
        )
        .max_gas()
        .transact()
        .await
        .unwrap();
    let result: bool = result.json().unwrap();
    assert!(result);

    // Upgrade the bridge token directly because self-upgrade is not supported in version `0.1.6`
    let _token_contract = token_account
        .deploy(&std::fs::read(BRIDGE_TOKEN_WASM_PATH).unwrap())
        .await
        .unwrap()
        .result;

    // Verify the bridge token version
    let token_version: String = worker
        .view(token_account.id(), "version")
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(token_version, "0.2.1");

    // Upgrade the bridge token over factory (redeploy the same version)
    let result = alice
        .call(factory.id(), "upgrade_bridge_token")
        .args(
            json!({"address": DAI_ADDRESS.to_string()})
                .to_string()
                .into_bytes(),
        )
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(result.is_success());

    // Verify the bridge token version
    let token_version: String = worker
        .view(token_account.id(), "version")
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(token_version, "0.2.1");

    // Grant alice the `PauseManager` role
    let result = alice
        .call(factory.id(), "acl_grant_role")
        .args(
            json!({
               "role": "PauseManager",
               "account_id": alice.id().to_string()
            })
            .to_string()
            .into_bytes(),
        )
        .max_gas()
        .transact()
        .await
        .unwrap();
    let result: bool = result.json().unwrap();
    assert!(result);

    // Pause bridge token withdraw
    let result = alice
        .call(factory.id(), "set_paused_withdraw")
        .args(
            json!({"address": DAI_ADDRESS.to_string(), "paused": true})
                .to_string()
                .into_bytes(),
        )
        .max_gas()
        .transact()
        .await
        .unwrap();
    println!("{:?}", result);
    assert!(result.is_success());

    // Verify bridge token is paused
    let is_paused: bool = alice
        .call(token_account.id(), "is_paused")
        .max_gas()
        .transact()
        .await
        .unwrap()
        .json()
        .unwrap();
    assert!(is_paused);
}

#[tokio::test]
async fn test_attach_full_access_key() {
    let (alice, factory, worker) = create_contract(FACTORY_WASM_PATH).await;

    let token_account = Account::from_secret_key(
        format!("{}.{}", DAI_ADDRESS, factory.id()).parse().unwrap(),
        factory.as_account().secret_key().clone(),
        &worker,
    );

    // Grant alice the `DAO` role
    let result = factory
        .call("acl_grant_role")
        .args_json(json!({
           "role": "DAO",
           "account_id": alice.id().to_string()
        }))
        .max_gas()
        .transact()
        .await
        .unwrap();
    let result: bool = result.json().unwrap();
    assert!(result);

    assert!(alice
        .call(factory.id(), "deploy_bridge_token")
        .deposit(35 * ONE_NEAR)
        .args(
            json!({"address": DAI_ADDRESS.to_string()})
                .to_string()
                .into_bytes()
        )
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    let token_account_id: String = factory
        .view("get_bridge_token_account_id")
        .args_json(json!({"address": DAI_ADDRESS.to_string()}))
        .await
        .unwrap()
        .json()
        .unwrap();

    assert_eq!(token_account_id, token_account.id().to_string());

    let ed_pk_str = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";

    // Add new full access key to the factory contract
    assert!(alice
        .call(factory.id(), "attach_full_access_key")
        .args_json(json!({ "public_key": ed_pk_str }))
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    let keys: Vec<String> = factory
        .view_access_keys()
        .await
        .unwrap()
        .iter()
        .map(|info| info.public_key.to_string())
        .collect();

    // Check that the access key is added to the factory contract
    assert!(keys.len() == 2 && keys.contains(&ed_pk_str.to_string()));

    assert!(alice
        .call(factory.id(), "attach_full_access_key_to_token")
        .args_json(json!({ "public_key": ed_pk_str, "address": DAI_ADDRESS }))
        .max_gas()
        .transact()
        .await
        .unwrap()
        .is_success());

    let keys: Vec<String> = token_account
        .view_access_keys()
        .await
        .unwrap()
        .iter()
        .map(|info| info.public_key.to_string())
        .collect();

    // Check that the access key is added to the bridge contract
    assert!(keys.len() == 1 && keys.contains(&ed_pk_str.to_string()));
}
