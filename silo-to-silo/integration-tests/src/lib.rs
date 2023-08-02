#[cfg(test)]
mod tests {
    use aurora_sdk_integration_tests::aurora_engine::erc20::ERC20;
    use aurora_sdk_integration_tests::aurora_engine_types::parameters::engine::{
        SubmitResult, TransactionStatus,
    };
    use aurora_sdk_integration_tests::aurora_engine_types::H160;
    use aurora_sdk_integration_tests::workspaces::result::ExecutionFinalResult;
    use aurora_sdk_integration_tests::workspaces::{Account, Contract};
    use aurora_sdk_integration_tests::{
        aurora_engine::{self, AuroraEngine},
        aurora_engine_types::{
            parameters::engine::{CallArgs, FunctionCallArgsV1},
            types::{Address, Wei},
            U256,
        },
        ethabi, tokio,
        utils::{ethabi::DeployedContract, forge, process},
        wnear,
        workspaces::{self, AccountId},
    };
    use std::path::Path;

    const ATTACHED_NEAR: u128 = 5_000_000_000_000_000_000_000_000;
    const NEAR_DEPOSIT: u128 = 2_000_000_000_000_000_000_000_000;

    const TRANSFER_TOKENS_AMOUNT: u64 = 100;
    const TOKEN_SUPPLY: u64 = 1000000000;

    #[tokio::test]
    async fn test_ft_transfer_to_silo() {
        let worker = workspaces::sandbox().await.unwrap();
        let engine = aurora_engine::deploy_latest(&worker, "aurora.test.near")
            .await
            .unwrap();
        let silo = aurora_engine::deploy_latest(&worker, "silo.test.near")
            .await
            .unwrap();

        let engine_wnear = wnear::Wnear::deploy(&worker, &engine).await.unwrap();

        let user_account = worker.dev_create_account().await.unwrap();
        let user_address =
            aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                user_account.id().as_bytes(),
            );

        let engine_silo_to_silo_contract = deploy_silo_to_silo_sol_contract(
            &engine,
            &user_account,
            engine_wnear.aurora_token.address,
        )
        .await;

        let mock_token = deploy_mock_token(&worker, user_account.id()).await;
        let engine_mock_token = engine.bridge_nep141(mock_token.id()).await.unwrap();
        let silo_mock_token = silo.bridge_nep141(mock_token.id()).await.unwrap();

        engine
            .mint_wnear(
                &engine_wnear,
                user_address,
                2 * (ATTACHED_NEAR + NEAR_DEPOSIT),
            )
            .await
            .unwrap();

        approve_spend_tokens(
            &engine_wnear.aurora_token,
            engine_silo_to_silo_contract.address,
            &user_account,
            &engine,
        )
        .await;
        mint_tokens_near(&mock_token, engine.inner.id()).await;

        silo_to_silo_register_token(
            &engine_silo_to_silo_contract,
            engine_mock_token.address.raw(),
            mock_token.id().to_string(),
            &user_account,
            &engine,
        )
        .await;
        check_token_account_id(
            &engine_silo_to_silo_contract,
            engine_mock_token.address.raw(),
            mock_token.id().to_string(),
            &user_account,
            &engine,
        )
        .await;
        check_near_account_id(&engine_silo_to_silo_contract, &user_account, &engine).await;

        storage_deposit(&mock_token, engine.inner.id()).await;
        storage_deposit(&mock_token, silo.inner.id()).await;

        engine_mint_tokens(user_address, &engine_mock_token, &engine).await;
        approve_spend_tokens(
            &engine_mock_token,
            engine_silo_to_silo_contract.address,
            &user_account,
            &engine,
        )
        .await;

        let balance_engine_before = engine
            .erc20_balance_of(&engine_mock_token, user_address)
            .await
            .unwrap();
        silo_to_silo_transfer(
            &engine_silo_to_silo_contract,
            &engine_mock_token,
            engine.inner.id(),
            silo.inner.id(),
            user_account.clone(),
            user_address.encode(),
            true
        )
        .await;

        let balance_engine_after = engine
            .erc20_balance_of(&engine_mock_token, user_address)
            .await
            .unwrap();
        assert_eq!(
            (balance_engine_before - balance_engine_after).as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        let balance_silo = silo
            .erc20_balance_of(&silo_mock_token, user_address)
            .await
            .unwrap();
        assert_eq!(balance_silo.as_u64(), TRANSFER_TOKENS_AMOUNT);

        // Transfer from silo back to aurora
        let silo_wnear = wnear::Wnear::deploy(&worker, &silo).await.unwrap();
        let silo_silo_to_silo_contract =
            deploy_silo_to_silo_sol_contract(&silo, &user_account, silo_wnear.aurora_token.address)
                .await;

        silo.mint_wnear(
            &silo_wnear,
            user_address,
            2 * (ATTACHED_NEAR + NEAR_DEPOSIT),
        )
        .await
        .unwrap();

        approve_spend_tokens(
            &silo_wnear.aurora_token,
            silo_silo_to_silo_contract.address,
            &user_account,
            &silo,
        )
        .await;

        silo_to_silo_register_token(
            &silo_silo_to_silo_contract,
            silo_mock_token.address.raw(),
            mock_token.id().to_string(),
            &user_account,
            &silo,
        )
        .await;

        check_token_account_id(
            &silo_silo_to_silo_contract,
            silo_mock_token.address.raw(),
            mock_token.id().to_string(),
            &user_account,
            &silo,
        )
        .await;

        approve_spend_tokens(
            &silo_mock_token,
            silo_silo_to_silo_contract.address,
            &user_account,
            &silo,
        )
        .await;

        silo_to_silo_transfer(
            &silo_silo_to_silo_contract,
            &silo_mock_token,
            silo.inner.id(),
            engine.inner.id(),
            user_account,
            user_address.encode(),
            true
        )
        .await;

        let balance_engine_after_silo = engine
            .erc20_balance_of(&engine_mock_token, user_address)
            .await
            .unwrap();
        assert_eq!(
            (balance_engine_after_silo - balance_engine_after).as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        let balance_silo = silo
            .erc20_balance_of(&silo_mock_token, user_address)
            .await
            .unwrap();
        assert_eq!(balance_silo.as_u64(), 0);
    }

    #[tokio::test]
    async fn test_withdraw() {
        let worker = workspaces::sandbox().await.unwrap();
        let engine = aurora_engine::deploy_latest(&worker, "aurora.test.near")
            .await
            .unwrap();
        let silo = aurora_engine::deploy_latest(&worker, "silo.test.near")
            .await
            .unwrap();

        let engine_wnear = wnear::Wnear::deploy(&worker, &engine).await.unwrap();

        let user_account = worker.dev_create_account().await.unwrap();
        let user_address =
            aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                user_account.id().as_bytes(),
            );

        let engine_silo_to_silo_contract = deploy_silo_to_silo_sol_contract(
            &engine,
            &user_account,
            engine_wnear.aurora_token.address,
        )
            .await;

        let mock_token = deploy_mock_token(&worker, user_account.id()).await;
        let engine_mock_token = engine.bridge_nep141(mock_token.id()).await.unwrap();
        let silo_mock_token = silo.bridge_nep141(mock_token.id()).await.unwrap();

        engine
            .mint_wnear(
                &engine_wnear,
                user_address,
                2 * (ATTACHED_NEAR + NEAR_DEPOSIT),
            )
            .await
            .unwrap();

        approve_spend_tokens(
            &engine_wnear.aurora_token,
            engine_silo_to_silo_contract.address,
            &user_account,
            &engine,
        )
            .await;
        mint_tokens_near(&mock_token, engine.inner.id()).await;

        silo_to_silo_register_token(
            &engine_silo_to_silo_contract,
            engine_mock_token.address.raw(),
            mock_token.id().to_string(),
            &user_account,
            &engine,
        )
            .await;
        check_token_account_id(
            &engine_silo_to_silo_contract,
            engine_mock_token.address.raw(),
            mock_token.id().to_string(),
            &user_account,
            &engine,
        )
            .await;
        check_near_account_id(&engine_silo_to_silo_contract, &user_account, &engine).await;

        storage_deposit(&mock_token, engine.inner.id()).await;

        engine_mint_tokens(user_address, &engine_mock_token, &engine).await;
        approve_spend_tokens(
            &engine_mock_token,
            engine_silo_to_silo_contract.address,
            &user_account,
            &engine,
        ).await;

        let balance_engine_before = engine
            .erc20_balance_of(&engine_mock_token, user_address)
            .await
            .unwrap();
        silo_to_silo_transfer(
            &engine_silo_to_silo_contract,
            &engine_mock_token,
            engine.inner.id(),
            silo.inner.id(),
            user_account.clone(),
            user_address.encode(),
            false
        )
            .await;

        let balance_engine_after = engine
            .erc20_balance_of(&engine_mock_token, user_address)
            .await
            .unwrap();
        assert_eq!(
            (balance_engine_before - balance_engine_after).as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        let balance_silo = silo
            .erc20_balance_of(&silo_mock_token, user_address)
            .await
            .unwrap();
        assert_eq!(balance_silo.as_u64(), 0);

        check_get_user_balance(
            &engine_silo_to_silo_contract,
            &user_account,
            engine_mock_token.address.raw(),
            user_address.raw(),
            &engine,
            100
        ).await;

        withdraw(&engine_silo_to_silo_contract, &engine_mock_token, engine.inner.id(), user_account.clone()).await;

        let balance_engine_after_withdraw = engine
            .erc20_balance_of(&engine_mock_token, user_address)
            .await
            .unwrap();

        assert_eq!(balance_engine_before, balance_engine_after_withdraw);

        check_get_user_balance(
            &engine_silo_to_silo_contract,
            &user_account,
            engine_mock_token.address.raw(),
            user_address.raw(),
            &engine,
            0
        ).await;
    }

    async fn deploy_silo_to_silo_sol_contract(
        engine: &AuroraEngine,
        user_account: &workspaces::Account,
        wnear_address: Address,
    ) -> DeployedContract {
        let contract_path = "../contracts";

        let aurora_sdk_path = Path::new("./aurora-contracts-sdk/aurora-solidity-sdk");
        let codec_lib = forge::deploy_codec_lib(&aurora_sdk_path, engine)
            .await
            .unwrap();
        let utils_lib = forge::deploy_utils_lib(&aurora_sdk_path, engine)
            .await
            .unwrap();
        let aurora_sdk_lib =
            forge::deploy_aurora_sdk_lib(&aurora_sdk_path, engine, codec_lib, utils_lib)
                .await
                .unwrap();

        let constructor = forge::forge_build(
            contract_path,
            &[
                format!(
                    "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol:AuroraSdk:0x{}",
                    aurora_sdk_lib.encode()
                ),
                format!(
                    "@auroraisnear/aurora-sdk/aurora-sdk/Utils.sol:Utils:0x{}",
                    utils_lib.encode()
                ),
            ],
            &["out", "SiloToSilo.sol", "SiloToSilo.json"],
        )
        .await
        .unwrap();

        let deploy_bytes = constructor.create_deploy_bytes_with_args(&[
            ethabi::Token::Address(wnear_address.raw()),
            ethabi::Token::String(engine.inner.id().to_string()),
        ]);

        let address = engine
            .deploy_evm_contract_with(user_account, deploy_bytes)
            .await
            .unwrap();

        constructor.deployed_at(address)
    }

    async fn deploy_mock_token(
        worker: &workspaces::Worker<workspaces::network::Sandbox>,
        user_account_id: &str,
    ) -> workspaces::Contract {
        let contract_path = Path::new("./mock_token");
        let output = tokio::process::Command::new("cargo")
            .current_dir(contract_path)
            .env("RUSTFLAGS", "-C link-arg=-s")
            .args([
                "build",
                "--all",
                "--target",
                "wasm32-unknown-unknown",
                "--release",
            ])
            .output()
            .await
            .unwrap();
        process::require_success(&output).unwrap();
        let artifact_path =
            contract_path.join("target/wasm32-unknown-unknown/release/mock_token.wasm");
        let wasm_bytes = tokio::fs::read(artifact_path).await.unwrap();
        let mock_token = worker.dev_deploy(&wasm_bytes).await.unwrap();

        mock_token
            .call("new_default_meta")
            .args_json(serde_json::json!({"owner_id": user_account_id, "name": "MockToken", "symbol": "MCT", "total_supply": format!("{}", TOKEN_SUPPLY)}))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();

        mock_token
    }

    async fn mint_tokens_near(token_contract: &Contract, receiver_id: &str) {
        token_contract
            .call("mint")
            .args_json(serde_json::json!({
                "account_id": receiver_id,
                "amount": format!("{}", TOKEN_SUPPLY)
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();
    }

    async fn approve_spend_tokens(
        token_contract: &ERC20,
        spender_address: Address,
        user_account: &Account,
        engine: &AuroraEngine,
    ) {
        let evm_input = token_contract.create_approve_call_bytes(spender_address, U256::MAX);
        let result = engine
            .call_evm_contract_with(user_account, token_contract.address, evm_input, Wei::zero())
            .await
            .unwrap();
        aurora_engine::unwrap_success(result.status).unwrap();
    }

    async fn silo_to_silo_register_token(
        silo_to_silo_contract: &DeployedContract,
        engine_mock_token_address: H160,
        near_mock_token_account_id: String,
        user_account: &Account,
        engine: &AuroraEngine,
    ) {
        let contract_args = silo_to_silo_contract.create_call_method_bytes_with_args(
            "registerToken",
            &[
                ethabi::Token::Address(engine_mock_token_address),
                ethabi::Token::String(near_mock_token_account_id),
            ],
        );

        call_aurora_contract(
            silo_to_silo_contract.address,
            contract_args,
            user_account,
            engine.inner.id(),
            true
        )
        .await
        .unwrap();
    }

    async fn check_token_account_id(
        silo_to_silo_contract: &DeployedContract,
        engine_mock_token_address: H160,
        near_mock_token_account_id: String,
        user_account: &Account,
        engine: &AuroraEngine,
    ) {
        let contract_args = silo_to_silo_contract.create_call_method_bytes_with_args(
            "getTokenAccountId",
            &[ethabi::Token::Address(engine_mock_token_address)],
        );

        let outcome = call_aurora_contract(
            silo_to_silo_contract.address,
            contract_args,
            user_account,
            engine.inner.id(),
            true
        )
        .await;

        let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
        if let TransactionStatus::Succeed(res) = result.status {
            let str_res = std::str::from_utf8(&res).unwrap();
            assert!(str_res.contains(&near_mock_token_account_id));
        }
    }

    async fn check_near_account_id(
        silo_to_silo_contract: &DeployedContract,
        user_account: &Account,
        engine: &AuroraEngine,
    ) {
        let contract_args =
            silo_to_silo_contract.create_call_method_bytes_with_args("getNearAccountId", &[]);

        let outcome = call_aurora_contract(
            silo_to_silo_contract.address,
            contract_args,
            user_account,
            engine.inner.id(),
            true
        )
        .await;

        let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
        if let TransactionStatus::Succeed(res) = result.status {
            let str_res = std::str::from_utf8(&res).unwrap();
            assert!(str_res.contains(&silo_to_silo_contract.address.encode()));
        }
    }

    async fn check_get_user_balance(
        silo_to_silo_contract: &DeployedContract,
        user_account: &Account,
        engine_mock_token_address: H160,
        user_address: H160,
        engine: &AuroraEngine,
        expected_value: u8
    ) {
        let contract_args =
            silo_to_silo_contract.create_call_method_bytes_with_args("getUserBalance",
                                                                     &[ethabi::Token::Address(engine_mock_token_address),
                                                                         ethabi::Token::Address(user_address)]);
        let outcome = call_aurora_contract(
            silo_to_silo_contract.address,
            contract_args,
            user_account,
            engine.inner.id(),
            true
        )
            .await;

        let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
        if let TransactionStatus::Succeed(res) = result.status {
             assert_eq!(res[res.len() - 1], expected_value);
        }
    }

    async fn storage_deposit(token_contract: &Contract, account_id: &str) {
        let outcome = token_contract
            .call("storage_deposit")
            .args_json(serde_json::json!({ "account_id": account_id }))
            .max_gas()
            .deposit(1_250_000_000_000_000_000_000)
            .transact()
            .await
            .unwrap();

        assert!(
            outcome.failures().is_empty(),
            "Call to set failed: {:?}",
            outcome.failures()
        );
    }

    async fn engine_mint_tokens(
        user_address: Address,
        token_account: &ERC20,
        engine: &AuroraEngine,
    ) {
        let mint_args =
            token_account.create_mint_call_bytes(user_address, U256::from(TRANSFER_TOKENS_AMOUNT));
        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: token_account.address,
            input: mint_args.0,
        });

        let outcome = engine
            .inner
            .call("call")
            .args_borsh(call_args)
            .max_gas()
            .transact()
            .await
            .unwrap();

        assert!(
            outcome.failures().is_empty(),
            "Call to set failed: {:?}",
            outcome.failures()
        );

        let balance = engine
            .erc20_balance_of(&token_account, user_address)
            .await
            .unwrap();
        assert_eq!(balance.as_u64(), TRANSFER_TOKENS_AMOUNT);
    }

    async fn silo_to_silo_transfer(
        silo_to_silo_contract: &DeployedContract,
        token_account: &ERC20,
        silo1_address: &AccountId,
        silo2_address: &AccountId,
        user_account: Account,
        user_address: String,
        check_output: bool
    ) {
        let contract_args = silo_to_silo_contract.create_call_method_bytes_with_args(
            "ftTransferCallToNear",
            &[
                ethabi::Token::Address(token_account.address.raw()),
                ethabi::Token::Uint(U256::from(TRANSFER_TOKENS_AMOUNT)),
                ethabi::Token::String(silo2_address.to_string()),
                ethabi::Token::String(user_address),
            ],
        );

        call_aurora_contract(
            silo_to_silo_contract.address,
            contract_args,
            &user_account,
            silo1_address,
            check_output
        )
        .await
        .unwrap();
    }

    async fn withdraw(
        silo_to_silo_contract: &DeployedContract,
        token_account: &ERC20,
        engine_address: &AccountId,
        user_account: Account,
    ) {
        let contract_args = silo_to_silo_contract.create_call_method_bytes_with_args(
            "withdraw",
            &[
                ethabi::Token::Address(token_account.address.raw()),
            ],
        );

        call_aurora_contract(
            silo_to_silo_contract.address,
            contract_args,
            &user_account,
            engine_address,
            true
        )
            .await
            .unwrap();
    }

    async fn call_aurora_contract(
        contract_address: Address,
        contract_args: Vec<u8>,
        user_account: &Account,
        engine_account: &AccountId,
        check_output: bool
    ) -> ExecutionFinalResult {
        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: contract_address,
            input: contract_args,
        });

        let outcome = user_account
            .call(engine_account, "call")
            .args_borsh(call_args)
            .max_gas()
            .transact()
            .await
            .unwrap();

        if check_output {
            assert!(
                outcome.failures().is_empty(),
                "Call to set failed: {:?}",
                outcome.failures()
            );
        }

        outcome
    }
}
