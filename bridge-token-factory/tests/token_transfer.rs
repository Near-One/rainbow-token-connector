use near_sdk::borsh::BorshSerialize;
use near_sdk::{AccountId, Balance};
use near_test::test_user::{init_test_runtime, TestRuntime, to_yocto, TxResult};
use serde_json::json;

use bridge_token_factory::prover::Proof;

const PROVER: &str = "prover";
const FACTORY: &str = "bridge";
const LOCKER_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";
const DAI_ADDRESS: &str = "6b175474e89094c44da98b954eedeac495271d0f";

lazy_static::lazy_static! {
    static ref FACTORY_WASM_BYTES: &'static [u8] = include_bytes!("../../res/bridge_token_factory.wasm").as_ref();
}

pub struct BridgeTokenFactory {
    contract_id: AccountId,
}

impl BridgeTokenFactory {
    pub fn new(runtime: &mut TestRuntime, signer_id: &AccountId, contract_id: AccountId, prover_account: AccountId, locker_address: String) -> Self {
        let _ = runtime
            .deploy(signer_id.clone(), contract_id.clone(), &FACTORY_WASM_BYTES, json!({"prover_account": prover_account, "locker_address": locker_address}))
            .unwrap();
        Self { contract_id }
    }

    pub fn mint(&self, runtime: &mut TestRuntime, signer_id: &AccountId, proof: Proof) -> TxResult {
        runtime.call(signer_id.clone(), self.contract_id.clone(), "mint", json!({"proof": proof.try_to_vec().unwrap()}), 0)
    }

    pub fn deploy_bridge_token(&self, runtime: &mut TestRuntime, signer_id: &AccountId, address: String, deposit: Balance) -> TxResult {
        runtime.call(signer_id.clone(), self.contract_id.clone(), "deploy_bridge_token", json!({"address": address}), deposit)
    }
}

#[test]
fn deploy_bridge_token() {
    let mut runtime = init_test_runtime();
    let root = "root".to_string();
    let factory = BridgeTokenFactory::new(&mut runtime, &root, FACTORY.to_string(), PROVER.to_string(), LOCKER_ADDRESS.to_string());
    let proof = Proof { log_index: 0, log_entry_data: vec![], receipt_index: 0, receipt_data: vec![], header_data: vec![], proof: vec![] };
    // Fails with not enough deposit.
    factory.deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), 0).unwrap_err();
    // Deploys the contract.
    factory.deploy_bridge_token(&mut runtime, &root, DAI_ADDRESS.to_string(), to_yocto("30")).unwrap();
}
