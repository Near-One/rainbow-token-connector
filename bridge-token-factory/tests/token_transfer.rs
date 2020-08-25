use borsh::BorshSerialize;
use near_sdk::{AccountId, Balance};
use near_test::test_user::{init_test_runtime, to_yocto, TestRuntime, TxResult};
use serde_json::json;

use bridge_token_factory::prover::{EthEventData, Proof};

const PROVER: &str = "prover";
const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "11111474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const SENDER_ADDRESS: &str = "00005474e89094c44da98b954eedeac495271d0f";
const ALICE: &str = "alice";

lazy_static::lazy_static! {
    static ref MOCK_PROVER_WASM_BYTES: &'static [u8] = include_bytes!("../../res/mock_prover.wasm").as_ref();
    static ref FACTORY_WASM_BYTES: &'static [u8] = include_bytes!("../../res/bridge_token_factory.wasm").as_ref();
}

pub struct BridgeToken {
    pub contract_id: AccountId
}

impl BridgeToken {
    pub fn get_balance(&self, runtime: &mut TestRuntime, owner: String) -> String {
        runtime.view(self.contract_id.clone(), "get_balance", json!({"owner_id": owner})).as_str().unwrap().to_string()
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
}

#[test]
fn deploy_bridge_token() {
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
    // Fails with not enough deposit.
    factory
        .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), 0)
        .unwrap_err();
    // Deploys the contract.
    factory
        .deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("35"))
        .unwrap();

    let token_account_id =
        factory.get_bridge_token_account_id(&mut runtime, DAI_ADDRESS.to_string());
    assert_eq!(token_account_id, format!("{}.{}", DAI_ADDRESS, FACTORY));

    let token = BridgeToken { contract_id: token_account_id };
    assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "0");

    let data = hex::decode(LOCKER_ADDRESS).unwrap();
    let mut locker_address = [0u8; 20];
    locker_address.copy_from_slice(&data);
    let proof = Proof {
        log_index: 0,
        log_entry_data: EthEventData {
            locker_address,
            token: DAI_ADDRESS.to_string(),
            sender: SENDER_ADDRESS.to_string(),
            amount: 1_000,
            recipient: ALICE.to_string(),
        }
        .to_log_entry_data(),
        receipt_index: 0,
        receipt_data: vec![],
        header_data: vec![],
        proof: vec![],
    };
    factory.deposit(&mut runtime, &root, proof).unwrap();

    assert_eq!(token.get_balance(&mut runtime, ALICE.to_string()), "1000");
}
