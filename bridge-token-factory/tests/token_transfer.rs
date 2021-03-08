use near_sdk::borsh::BorshSerialize;
use near_sdk::{AccountId, Balance};
use serde_json::json;

use bridge_token::BridgeTokenContract;
use bridge_token_factory::BridgeTokenFactoryContract;
use bridge_token_factory::{validate_eth_address, EthLockedEvent, EthUnlockedEvent, Proof};
use mock_prover::MockProverContract;
use near_sdk_sim::{
    call, deploy, init_simulator, units::to_yocto, view, ContractAccount, UserAccount,
};
use test_token::ContractContract as TestTokenContract;

const PROVER: &str = "prover";
const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "11111474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const SENDER_ADDRESS: &str = "00005474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "alice";
const TEST_TOKEN: &str = "test-token";

near_sdk_sim::lazy_static_include::lazy_static_include_bytes! {
    TEST_TOKEN_WASM_BYTES => "../../res/test_token.wasm",
    FACTORY_WASM_BYTES => "../../res/bridge_token_factory.wasm",
    MOCK_PROVER_WASM_BYTES => "../../res/mock_prover.wasm",
}

fn setup_token_factory() -> (UserAccount, ContractAccount<BridgeTokenFactoryContract>) {
    let root = init_simulator(None);
    let prover = deploy!(
        contract: MockProverContract,
        contract_id: PROVER.to_string(),
        bytes: &MOCK_PROVER_WASM_BYTES,
        signer_account: root
    );
    let factory = deploy!(
        contract: BridgeTokenFactoryContract,
        contract_id: FACTORY.to_string(),
        bytes: &FACTORY_WASM_BYTES,
        signer_account: root,
        init_method: new(
            PROVER.to_string(), LOCKER_ADDRESS.to_string()
        )
    );
    let alice = root.create_user(ALICE.to_string(), to_yocto("100"));

    (root, factory)
}

#[test]
fn test_eth_token_transfer() {
    let (user, factory) = setup_token_factory();
    let root = "root".to_string();

    call!(
        user,
        factory.deploy_bridge_token(DAI_ADDRESS.to_string()),
        deposit = to_yocto("35")
    )
    .assert_success();

    let token_account_id: String =
        view!(factory.get_bridge_token_account_id(DAI_ADDRESS.to_string())).unwrap_json();
    assert_eq!(token_account_id, format!("{}.{}", DAI_ADDRESS, FACTORY));

    // TODO: use BridgeTokenContract
    // let token = BridgeToken {
    //     contract_id: token_account_id,
    // };
    // assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "0");
    // assert_eq!(token.get_total_supply(&mut runtime), "0");

    let mut proof = Proof::default();
    proof.log_entry_data = EthLockedEvent {
        locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
        token: DAI_ADDRESS.to_string(),
        sender: SENDER_ADDRESS.to_string(),
        amount: 1_000,
        recipient: ALICE.to_string(),
    }
    .to_log_entry_data();
    call!(user, factory.deposit(proof)).assert_success();

    // assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "1000");
    // assert_eq!(token.get_total_supply(&mut runtime), "1000");

    // token
    //     .withdraw(
    //         &mut runtime,
    //         ALICE.to_string(),
    //         "100".to_string(),
    //         SENDER_ADDRESS.to_string(),
    //     )
    //     .unwrap();
    //
    // assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "900");
    // assert_eq!(token.get_total_supply(&mut runtime), "900");
}

// #[test]
// fn test_with_invalid_proof() {
//     let (mut runtime, factory) = setup_token_factory();
//     let root = "root".to_string();
//
//     factory
//         .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
//         .unwrap();
//
//     let token_account_id =
//         factory.get_bridge_token_account_id(&mut runtime, DAI_ADDRESS.to_string());
//     assert_eq!(token_account_id, format!("{}.{}", DAI_ADDRESS, FACTORY));
//
//     let mut proof = Proof::default();
//
//     proof.log_entry_data = EthLockedEvent {
//         locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
//         token: DAI_ADDRESS.to_string(),
//         sender: SENDER_ADDRESS.to_string(),
//         amount: 1_000,
//         recipient: ALICE.to_string(),
//     }
//     .to_log_entry_data();
//
//     // This is an invalid proof that will not pass proof validation
//     // since mock_prover will only accept empty proofs.
//     proof.proof = vec![vec![]];
//
//     factory
//         .deposit(&mut runtime, &root, proof.clone())
//         .unwrap_err();
//
//     // Convert the proof in a valid proof that is going to be accepted by the mock_prover.
//     proof.proof.clear();
//
//     // This deposit event must succeed. Notice that previously a similar deposit
//     // was made, but it failed because it had an invalid proof, so this one should succeed.
//     factory.deposit(&mut runtime, &root, proof.clone()).unwrap();
//
//     // This deposit event must fail since same deposit event can't be reused.
//     // Previous call to deposit with the same event was successful.
//     factory.deposit(&mut runtime, &root, proof).unwrap_err();
// }
//
// #[test]
// fn test_near_token_transfer() {
//     let (mut runtime, factory) = setup_token_factory();
//     let root = "root".to_string();
//     let token = deploy!(
//         contract: TestTokenContract,
//         contract_id: TEST_TOKEN.to_string(),
//         bytes: &TEST_TOKEN_WASM_BYTES,
//         signer_account: root
//     );
//     token.mint(root, to_yocto("1000")).unwrap();
//     token.ft_trasnfer_call(FACTORY.to_string(), to_yocto("100"), SENDER_ADDRESS.to_string()).unwrap();
//     assert_eq!(
//         token.ft_balance_of(&mut runtime, root.clone()),
//         to_yocto("900").to_string()
//     );
//     assert_eq!(
//         token.ft_total_supply(&mut runtime),
//         to_yocto("1000").to_string()
//     );
//
//     let mut proof = Proof::default();
//     proof.log_entry_data = EthUnlockedEvent {
//         locker_address: validate_eth_address(LOCKER_ADDRESS.to_string()),
//         token: TEST_TOKEN.to_string(),
//         sender: SENDER_ADDRESS.to_string(),
//         amount: 50 * 10u128.pow(24),
//         recipient: ALICE.to_string(),
//     }
//     .to_log_entry_data();
//     factory.unlock(&mut runtime, root.clone(), proof).unwrap();
//     assert_eq!(
//         token.get_balance(&mut runtime, ALICE.to_string()),
//         to_yocto("50").to_string()
//     );
//     assert_eq!(
//         token.get_total_supply(&mut runtime),
//         to_yocto("1000").to_string()
//     );
// }
//
// #[test]
// fn test_bridge_token_failures() {
//     let (mut runtime, factory) = setup_token_factory();
//     let root = "root".to_string();
//
//     factory
//         .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
//         .unwrap();
//     // let token = BridgeToken {
//     //     contract_id: format!("{}.{}", DAI_ADDRESS, FACTORY),
//     // };
//     //
//     // // Fail to withdraw because no coins.
//     // token
//     //     .withdraw(
//     //         &mut runtime,
//     //         root.clone(),
//     //         "100".to_string(),
//     //         SENDER_ADDRESS.to_string(),
//     //     )
//     //     .unwrap_err();
//     //
//     // // Fail to mint because sender is not controller.
//     // token
//     //     .mint(
//     //         &mut runtime,
//     //         root.clone(),
//     //         ALICE.to_string(),
//     //         "100".to_string(),
//     //     )
//     //     .unwrap_err();
// }
//
// /// TODO: instead of just unwrap_err check the specific errors.
// #[test]
// fn test_deploy_failures() {
//     let (mut runtime, factory) = setup_token_factory();
//     let root = "root".to_string();
//
//     // Fails with not enough deposit.
//     factory
//         .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), 0)
//         .unwrap_err();
//
//     // Fails with address is invalid.
//     factory
//         .deploy_bridge_token(
//             &mut runtime,
//             &root,
//             "not_a_hex".to_string(),
//             to_yocto("100"),
//         )
//         .unwrap_err();
//
//     // Fails second time because already exists.
//     factory
//         .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
//         .unwrap();
//     factory
//         .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
//         .unwrap_err();
// }
