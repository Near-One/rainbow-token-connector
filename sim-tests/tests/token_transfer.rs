use aurora_engine_parameters::{
    CallArgs, FunctionCallArgsV2, RawU256, SubmitResult, TransactionStatus, WeiU256,
};
use aurora_engine_types::{
    types::{u256_to_arr, Address},
    U256,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::AccountId;
use near_sdk_sim::{units::to_yocto, UserAccount};
use serde_json::json;

const AURORA: &str = "aurora";
const FACTORY: &str = "bridge";
const ALICE: &str = "alice";

near_sdk_sim::lazy_static_include::lazy_static_include_bytes! {
    FACTORY_WASM_BYTES => "../res/bridge_aurora_token_factory.wasm",
    AURORA_WASM_BYTES => "../res/mainnet-test.wasm",
}

pub const DEFAULT_GAS: u64 = 300_000_000_000_000;
pub const STORAGE_AMOUNT: u128 = 50_000_000_000_000_000_000_000_000;

/// Borsh-encoded parameters for the `new` function.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct NewCallArgs {
    /// Chain id, according to the EIP-115 / ethereum-lists spec.
    pub chain_id: RawU256,
    /// Account which can upgrade this contract.
    /// Use empty to disable updatability.
    pub owner_id: AccountId,
    /// Account of the bridge prover.
    /// Use empty to not use base token as bridged asset.
    pub bridge_prover_id: AccountId,
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
}

pub(crate) fn str_to_account_id(account_id: &str) -> AccountId {
    use aurora_engine_types::str::FromStr;
    AccountId::from_str(account_id).unwrap()
}

pub fn accounts(id: usize) -> AccountId {
    use aurora_engine_types::str::FromStr;
    AccountId::from_str(&["alice", "bob", "charlie", "danny", "eugene", "fargo"][id].to_string())
        .unwrap()
}

struct TestContext {
    root: UserAccount,
    aurora: UserAccount,
    factory: UserAccount,
    locker: Address,
    erc20: Address,
    nep141: AccountId,
}

/// Fungible token Reference hash type.
/// Used for FungibleTokenMetadata
#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct FungibleReferenceHash([u8; 32]);

#[derive(BorshDeserialize, BorshSerialize, Clone)]
pub struct FungibleTokenMetadata {
    pub spec: String,
    pub name: String,
    pub symbol: String,
    pub icon: Option<String>,
    pub reference: Option<String>,
    pub reference_hash: Option<FungibleReferenceHash>,
    pub decimals: u8,
}

impl Default for FungibleTokenMetadata {
    fn default() -> Self {
        Self {
            spec: "ft-1.0.0".to_string(),
            name: "Ether".to_string(),
            symbol: "ETH".to_string(),
            icon: Some("data:image/png;base64,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".to_string()),
            reference: None,
            reference_hash: None,
            decimals: 18,
        }
    }
}

/// Eth-connector initial args
#[derive(BorshSerialize, BorshDeserialize)]
pub struct InitCallArgs {
    pub prover_account: AccountId,
    pub eth_custodian_address: String,
    pub metadata: FungibleTokenMetadata,
}

/// Borsh-encoded parameters for `deploy_erc20_token` function.
#[derive(BorshSerialize, BorshDeserialize, Debug, Eq, PartialEq, Clone)]
pub struct DeployErc20TokenArgs {
    pub nep141: AccountId,
}

pub fn unwrap_success(result: SubmitResult) -> Vec<u8> {
    match result.status {
        TransactionStatus::Succeed(ret) => ret,
        other => panic!("Unexpected status: {:?}", other),
    }
}

pub fn unwrap_success_slice(result: &SubmitResult) -> &[u8] {
    match &result.status {
        TransactionStatus::Succeed(ret) => &ret,
        other => panic!("Unexpected status: {:?}", other),
    }
}

pub fn deploy_evm(main_account: &UserAccount) -> UserAccount {
    let evm_wasm_bytes = std::fs::read("../res/mainnet-test.wasm").unwrap();

    let contract_account = main_account.deploy(
        &evm_wasm_bytes,
        AURORA.parse().unwrap(),
        5 * near_sdk_sim::STORAGE_AMOUNT,
    );
    let prover_account = str_to_account_id("prover.near");
    let new_args = NewCallArgs {
        chain_id: u256_to_arr(&U256::from(1313161556)),
        owner_id: str_to_account_id(main_account.account_id.clone().as_str()),
        bridge_prover_id: prover_account.clone(),
        upgrade_delay_blocks: 1,
    };
    main_account
        .call(
            contract_account.account_id.clone(),
            "new",
            &new_args.try_to_vec().unwrap(),
            near_sdk_sim::DEFAULT_GAS,
            0,
        )
        .assert_success();
    let init_args = InitCallArgs {
        prover_account,
        eth_custodian_address: "d045f7e19B2488924B97F9c145b5E51D0D895A65".to_string(),
        metadata: Default::default(),
    };
    contract_account
        .call(
            contract_account.account_id.clone(),
            "new_eth_connector",
            &init_args.try_to_vec().unwrap(),
            near_sdk_sim::DEFAULT_GAS,
            0,
        )
        .assert_success();

    contract_account
}

fn deploy_factory(
    root: &UserAccount,
    aurora: String,
    locker: String,
    factory: String,
) -> UserAccount {
    let wasm_bytes = std::fs::read("../res/bridge_aurora_token_factory.wasm").unwrap();
    let contract_account = root.deploy(
        &wasm_bytes,
        factory.parse().unwrap(),
        near_sdk_sim::STORAGE_AMOUNT,
    );

    root.call(
        contract_account.account_id.clone(),
        "new",
        json!({
            "aurora_account": aurora,
            "locker_address": locker,
        })
        .to_string()
        .as_bytes(),
        near_sdk_sim::DEFAULT_GAS,
        0,
    )
    .assert_success();

    contract_account
}

fn deploy_locker(
    main_account: &UserAccount,
    aurora_account: &UserAccount,
    factory: String,
    async_aurora: String,
) -> Address {
    let erc20_locker_contract = include_bytes!("../../res/AuroraERC20Locker.bin");
    let admin =
        aurora_engine_sdk::types::near_account_to_evm_address(aurora_account.account_id.as_bytes());
    let deploy_args = ethabi::encode(&[
        ethabi::Token::String(factory),
        ethabi::Token::String(async_aurora),
        ethabi::Token::Address(admin.raw()),
        ethabi::Token::Uint(ethabi::Uint::from(0)),
    ]);

    let submit_result = main_account
        .call(
            aurora_account.account_id.clone(),
            "deploy_code",
            &[erc20_locker_contract, deploy_args.as_slice()]
                .concat()
                .to_vec(),
            near_sdk_sim::DEFAULT_GAS,
            0,
        )
        .unwrap_borsh();

    Address::try_from_slice(&unwrap_success(submit_result)).unwrap()
}

fn deploy_erc20_token(
    root: &UserAccount,
    nep_141: AccountId,
    aurora: AccountId,
    factory: AccountId,
) -> Address {
    let args = DeployErc20TokenArgs { nep141: nep_141 };
    let result = root.call(
        aurora.clone(),
        "deploy_erc20_token",
        &args.try_to_vec().unwrap(),
        near_sdk_sim::DEFAULT_GAS,
        0,
    );

    let addr_bytes: Vec<u8> = result.unwrap_borsh();
    let erc20_address = Address::try_from_slice(&addr_bytes).unwrap();
    root.call(
        factory.clone(),
        "deploy_bridge_token",
        &addr_bytes,
        near_sdk_sim::DEFAULT_GAS,
        0,
    );

    erc20_address
}

fn test_transfer_native_erc20_common() -> TestContext {
    let root = near_sdk_sim::init_simulator(None);
    let aurora = deploy_evm(&root);
    let locker = deploy_locker(
        &root,
        &aurora,
        FACTORY.to_string(),
        root.account_id().to_string(),
    );
    let factory = deploy_factory(
        &root,
        aurora.account_id.to_string(),
        locker.encode(),
        FACTORY.to_string(),
    );

    let erc20 = deploy_erc20_token(
        &root,
        "nep141".parse().unwrap(),
        aurora.account_id.clone(),
        factory.account_id.clone(),
    );
    let nep141: AccountId = format!("{}.{}", erc20.encode(), FACTORY).parse().unwrap();

    TestContext {
        root,
        aurora,
        factory,
        locker,
        erc20,
        nep141,
    }
}

fn build_input(str_selector: &str, inputs: &[ethabi::Token]) -> Vec<u8> {
    use sha3::Digest;
    let sel = sha3::Keccak256::digest(str_selector.as_bytes()).to_vec()[..4].to_vec();
    let inputs = ethabi::encode(inputs);
    [sel.as_slice(), inputs.as_slice()].concat().to_vec()
}

fn mint_erc20_token(context: &TestContext, dest: Address, amount: u128) {
    let input = build_input(
        "mint(address,uint256)",
        &[
            ethabi::Token::Address(dest.raw()),
            ethabi::Token::Uint(U256::from(amount).into()),
        ],
    );
    let call_args = CallArgs::V2(FunctionCallArgsV2 {
        contract: context.erc20.raw().into(),
        value: WeiU256::default(),
        input,
    });

    let result = context.aurora.call(
        context.aurora.account_id(),
        "call",
        &call_args.try_to_vec().unwrap(),
        near_sdk_sim::DEFAULT_GAS,
        0,
    );

    unwrap_success(result.unwrap_borsh());
}

fn approve_erc20_token(context: &TestContext, spender: Address, amount: u128) {
    let input = build_input(
        "approve(address,uint256)",
        &[
            ethabi::Token::Address(spender.raw()),
            ethabi::Token::Uint(U256::from(amount).into()),
        ],
    );

    let call_args = CallArgs::V2(FunctionCallArgsV2 {
        contract: context.erc20.raw().into(),
        value: WeiU256::default(),
        input,
    });

    let result = context.root.call(
        context.aurora.account_id(),
        "call",
        &call_args.try_to_vec().unwrap(),
        near_sdk_sim::DEFAULT_GAS,
        0,
    );

    unwrap_success(result.unwrap_borsh());
}

fn lock_erc20_token(context: &TestContext, recipient: String, amount: u128) -> Vec<u8> {
    let input = build_input(
        "lockTokenAsyncOnly(address,uint256,string)",
        &[
            ethabi::Token::Address(context.erc20.raw()),
            ethabi::Token::Uint(U256::from(amount).into()),
            ethabi::Token::String(recipient.into()),
        ],
    );

    let call_args = CallArgs::V2(FunctionCallArgsV2 {
        contract: context.locker.raw().into(),
        value: WeiU256::default(),
        input,
    });

    let result = context.root.call(
        context.aurora.account_id(),
        "call",
        &call_args.try_to_vec().unwrap(),
        near_sdk_sim::DEFAULT_GAS,
        0,
    );

    unwrap_success(result.unwrap_borsh())
}

fn erc20_balance(context: &TestContext, account: Address) -> U256 {
    let input = build_input(
        "balanceOf(address)",
        &[ethabi::Token::Address(account.raw())],
    );

    let call_args = CallArgs::V2(FunctionCallArgsV2 {
        contract: context.erc20.raw().into(),
        value: WeiU256::default(),
        input,
    });

    let result = context.root.call(
        context.aurora.account_id(),
        "call",
        &call_args.try_to_vec().unwrap(),
        near_sdk_sim::DEFAULT_GAS,
        0,
    );

    let submit_result: SubmitResult = result.unwrap_borsh();
    U256::from_big_endian(&unwrap_success(submit_result))
}

fn nep_141_balance_of(context: &TestContext, account_id: &str) -> u128 {
    context
        .root
        .call(
            context.nep141.clone(),
            "ft_balance_of",
            json!({ "account_id": account_id }).to_string().as_bytes(),
            near_sdk_sim::DEFAULT_GAS,
            0,
        )
        .unwrap_json_value()
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn test_native_erc20_token_transfer() {
    let context = test_transfer_native_erc20_common();
    let alice = context
        .root
        .create_user(ALICE.parse().unwrap(), to_yocto("100"));
    let root_address =
        aurora_engine_sdk::types::near_account_to_evm_address(&context.root.account_id.as_bytes());
    mint_erc20_token(&context, root_address, 1000);
    assert_eq!(U256::from(1000), erc20_balance(&context, root_address));

    approve_erc20_token(&context, context.locker, 100);
    let lock_result = lock_erc20_token(&context, ALICE.to_string(), 100);
    assert_eq!(U256::from(900), erc20_balance(&context, root_address));
    assert_eq!(
        U256::from(100),
        erc20_balance(&context, context.locker.clone())
    );

    let promise_args = json!({
        "token": "0x".to_string() + &context.erc20.encode(),
        "lock_event_index": "1",
    })
    .to_string();

    let promise_desc_str = format!(
        "promises:{}#{}#{}#{}",
        FACTORY.to_string(),
        "deposit",
        promise_args,
        "75000000000000"
    );
    let mut output_list =
        ethabi::decode(&[ethabi::ParamType::String], lock_result.as_slice()).unwrap();
    assert_eq!(output_list.pop().unwrap().to_string(), promise_desc_str);

    context
        .root
        .call(
            context.factory.account_id(),
            "deploy_bridge_token",
            &json!({
                "address": context.erc20.encode(),
            })
            .to_string()
            .as_bytes(),
            near_sdk_sim::DEFAULT_GAS,
            near_sdk_sim::STORAGE_AMOUNT,
        )
        .assert_success();

    context
        .root
        .call(
            context.factory.account_id(),
            "deposit",
            promise_args.as_bytes(),
            near_sdk_sim::DEFAULT_GAS,
            near_sdk_sim::STORAGE_AMOUNT,
        )
        .assert_success();

    // Test for double deposit
    assert_eq!(
        context
            .root
            .call(
                context.factory.account_id(),
                "deposit",
                promise_args.as_bytes(),
                near_sdk_sim::DEFAULT_GAS,
                near_sdk_sim::STORAGE_AMOUNT,
            )
            .is_ok(),
        false
    );

    assert_eq!(nep_141_balance_of(&context, ALICE), 100);

    alice
        .call(
            context.nep141.clone(),
            "withdraw",
            json!({ "amount": "50", "recipient": root_address.encode()})
                .to_string()
                .as_bytes(),
            near_sdk_sim::DEFAULT_GAS,
            1,
        )
        .assert_success();

    assert_eq!(nep_141_balance_of(&context, ALICE), 50);
    assert_eq!(
        U256::from(50),
        erc20_balance(&context, context.locker.clone())
    );
    assert_eq!(U256::from(950), erc20_balance(&context, root_address));
}
