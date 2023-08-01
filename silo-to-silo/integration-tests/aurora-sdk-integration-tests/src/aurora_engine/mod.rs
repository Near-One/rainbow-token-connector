use crate::wnear::Wnear;
use aurora_engine::parameters::{
    CallArgs, DeployErc20TokenArgs, FunctionCallArgsV2, NewCallArgs, NewCallArgsV2, SubmitResult,
    TransactionStatus, ViewCallArgs,
};
use aurora_engine_types::{
    types::{Address, Wei},
    U256,
};
use workspaces::{network::Sandbox, Contract, Worker};

pub mod erc20;
pub mod repo;

use erc20::ERC20DeployedAt;

const TESTNET_CHAIN_ID: u64 = 1313161555;

/// Newtype for bytes that are meant to be used as the input for an EVM contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractInput(pub Vec<u8>);

#[derive(Clone)]
pub struct AuroraEngine {
    pub inner: Contract,
}

pub async fn deploy_latest(worker: &Worker<Sandbox>, account_id: &str) -> anyhow::Result<AuroraEngine> {
    let wasm = repo::AuroraEngineRepo::download_and_compile_latest().await?;
    let (_, sk) = worker.dev_generate().await;
    // We can't use `dev-deploy` here because then the account ID is too long to create
    // `{address}.{engine}` sub-accounts.
    let contract = worker
        .create_tla_and_deploy(account_id.parse().unwrap(), sk, &wasm)
        .await?
        .into_result()?;
    let new_args = NewCallArgs::V2(NewCallArgsV2 {
        chain_id: aurora_engine_types::types::u256_to_arr(&TESTNET_CHAIN_ID.into()),
        owner_id: contract.id().as_ref().parse().unwrap(),
        upgrade_delay_blocks: 0,
    });

    // Initialize main contract
    contract
        .call("new")
        .args_borsh(new_args)
        .transact()
        .await?
        .into_result()?;
    let init_args = aurora_engine::parameters::InitCallArgs {
        prover_account: contract.id().as_ref().parse().unwrap(),
        eth_custodian_address: "0000000000000000000000000000000000000000".into(),
        metadata: Default::default(),
    };

    // Initialize connector
    contract
        .call("new_eth_connector")
        .args_borsh(init_args)
        .transact()
        .await?
        .into_result()?;

    // Initialize xcc router
    let router_wasm = repo::AuroraEngineRepo::download()
        .checkout(repo::LATEST_ENGINE_VERSION)
        .compile_xcc_router_contract()
        .execute()
        .await?;
    contract
        .call("factory_update")
        .args(router_wasm)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok(AuroraEngine { inner: contract })
}

impl AuroraEngine {
    pub async fn mint_account(
        &self,
        address: Address,
        init_nonce: u64,
        init_balance: Wei,
    ) -> anyhow::Result<()> {
        self.inner
            .call("mint_account")
            .args_borsh((address, init_nonce, init_balance.raw().low_u64()))
            .max_gas()
            .transact()
            .await?
            .into_result()?;
        Ok(())
    }

    pub async fn bridge_nep141(
        &self,
        nep141_id: &workspaces::AccountId,
    ) -> anyhow::Result<erc20::ERC20> {
        let args = DeployErc20TokenArgs {
            nep141: nep141_id.as_str().parse().unwrap(),
        };
        let outcome = self
            .inner
            .call("deploy_erc20_token")
            .args_borsh(args)
            .max_gas()
            .transact()
            .await?;
        let address_bytes: Vec<u8> = outcome.borsh()?;
        let address = Address::try_from_slice(&address_bytes).unwrap();
        let erc20 = erc20::Constructor::load().await?.deployed_at(address);
        Ok(erc20)
    }

    pub async fn mint_wnear(
        &self,
        wnear: &Wnear,
        dest_address: Address,
        amount: u128,
    ) -> anyhow::Result<()> {
        wnear.near_deposit(self.inner.as_account(), amount).await?;
        let result = self
            .call_evm_contract(
                wnear.aurora_token.address,
                wnear
                    .aurora_token
                    .create_mint_call_bytes(dest_address, amount.into()),
                Wei::zero(),
            )
            .await?;
        unwrap_success(result.status)?;
        Ok(())
    }

    pub async fn erc20_balance_of(
        &self,
        erc20: &erc20::ERC20,
        address: Address,
    ) -> anyhow::Result<U256> {
        let result = self
            .view_evm_contract(
                erc20.address,
                erc20.create_balance_of_call_bytes(address),
                None,
                Wei::zero(),
            )
            .await?;
        let balance = unwrap_success(result).map(|bytes| U256::from_big_endian(&bytes))?;
        Ok(balance)
    }

    pub async fn get_balance(&self, address: Address) -> anyhow::Result<Wei> {
        let outcome = self
            .inner
            .view("get_balance")
            .args(address.as_bytes().to_vec())
            .await?;
        Ok(Wei::new(U256::from_big_endian(&outcome.result)))
    }

    pub async fn deploy_evm_contract(&self, code: Vec<u8>) -> anyhow::Result<Address> {
        self.deploy_evm_contract_with(self.inner.as_account(), code)
            .await
    }

    pub async fn deploy_evm_contract_with(
        &self,
        account: &workspaces::Account,
        code: Vec<u8>,
    ) -> anyhow::Result<Address> {
        let outcome = account
            .call(self.inner.id(), "deploy_code")
            .args(code)
            .max_gas()
            .transact()
            .await?;
        let result: SubmitResult = outcome.borsh()?;
        let address = unwrap_success(result.status).and_then(|bytes| {
            Address::try_from_slice(&bytes)
                .map_err(|_| anyhow::Error::msg("Deploy result failed to parse as address"))
        })?;
        Ok(address)
    }

    pub async fn call_evm_contract(
        &self,
        address: Address,
        input: ContractInput,
        value: Wei,
    ) -> anyhow::Result<SubmitResult> {
        self.call_evm_contract_with(self.inner.as_account(), address, input, value)
            .await
    }

    pub async fn call_evm_contract_with(
        &self,
        account: &workspaces::Account,
        address: Address,
        input: ContractInput,
        value: Wei,
    ) -> anyhow::Result<SubmitResult> {
        let args = CallArgs::V2(FunctionCallArgsV2 {
            contract: address,
            value: value.to_bytes(),
            input: input.0,
        });
        let outcome = account
            .call(self.inner.id(), "call")
            .args_borsh(args)
            .max_gas()
            .transact()
            .await?;
        let result = outcome.borsh()?;
        Ok(result)
    }

    pub async fn view_evm_contract(
        &self,
        contract: Address,
        input: ContractInput,
        sender: Option<Address>,
        value: Wei,
    ) -> anyhow::Result<TransactionStatus> {
        let args = ViewCallArgs {
            sender: sender.unwrap_or_default(),
            address: contract,
            amount: value.to_bytes(),
            input: input.0,
        };
        let outcome = self
            .inner
            .call("view")
            .args_borsh(args)
            .max_gas()
            .transact()
            .await?;
        let result = outcome.borsh()?;
        Ok(result)
    }
}

pub fn unwrap_success(status: TransactionStatus) -> anyhow::Result<Vec<u8>> {
    match status {
        TransactionStatus::Succeed(bytes) => Ok(bytes),
        status => Err(anyhow::Error::msg(format!(
            "Transaction failed: {:?}",
            status
        ))),
    }
}
