#[cfg(test)]
mod tests {
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
    use aurora_sdk_integration_tests::aurora_engine_types::parameters::engine::{SubmitResult, TransactionStatus, ViewCallArgs};
    use serde_json::to_string;

    const ATTACHED_NEAR: u128 = 5_000_000_000_000_000_000_000_000;
    const NEAR_DEPOSIT: u128 = 2_000_000_000_000_000_000_000_000;

    #[tokio::test]
    async fn test_contract() {
        let worker = workspaces::sandbox().await.unwrap();
        let engine = aurora_engine::deploy_latest(&worker, "aurora.test.near").await.unwrap();
        let silo = aurora_engine::deploy_latest(&worker, "silo.test.near").await.unwrap();
        let engine_wnear = wnear::Wnear::deploy(&worker, &engine).await.unwrap();

        println!("{:?}", engine.inner.id().to_string());
        println!("{:?}", silo.inner.id().to_string());

        let user_account = worker.dev_create_account().await.unwrap();
        let user_address =
            aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                user_account.id().as_bytes(),
            );

        let engine_silo_to_silo_contract = deploy_silo_to_silo_sol_contract(
            &engine,
            &user_account,
            engine_wnear.aurora_token.address,
        ).await;

        let mock_token = deploy_mock_token(&worker).await;

        mock_token
            .call("new_default_meta")
            .args_json(serde_json::json!({"owner_id": user_account.id(), "name": "MockToken", "symbol": "MCT", "total_supply": "1000000"}))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();

        let engine_mock_token = engine.bridge_nep141(mock_token.id()).await.unwrap();
        let silo_mock_token = silo.bridge_nep141(mock_token.id()).await.unwrap();

        // Give user some wNEAR to use for XCC
        engine
            .mint_wnear(&engine_wnear, user_address, 2 * (ATTACHED_NEAR + NEAR_DEPOSIT))
            .await
            .unwrap();

        // Give user some wNEAR to use for XCC
        engine
            .mint_wnear(&engine_wnear, engine_silo_to_silo_contract.address, 2 * (ATTACHED_NEAR + NEAR_DEPOSIT))
            .await
            .unwrap();

        mock_token
            .call("mint")
            .args_json(serde_json::json!({
                "account_id": engine.inner.id(),
                "amount": "10000000000"
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();

        // Approve proxy contract to spend user's wNEAR
        let evm_input = engine_wnear
            .aurora_token
            .create_approve_call_bytes(engine_silo_to_silo_contract.address, U256::MAX);
        let result = engine
            .call_evm_contract_with(
                &user_account,
                engine_wnear.aurora_token.address,
                evm_input,
                Wei::zero(),
            )
            .await
            .unwrap();
        aurora_engine::unwrap_success(result.status).unwrap();

        let contract_args = engine_silo_to_silo_contract.create_call_method_bytes_with_args(
            "registerToken",
            &[
                ethabi::Token::Address(engine_mock_token.address.raw()),
                ethabi::Token::String( mock_token.id().to_string())
            ],
        );

        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: engine_silo_to_silo_contract.address,
            input: contract_args,
        });
        let outcome = user_account
            .call(engine.inner.id(), "call")
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


        //
        let contract_args = engine_silo_to_silo_contract.create_call_method_bytes_with_args(
            "getTokenAccountId",
            &[
                ethabi::Token::Address(engine_mock_token.address.raw())
            ],
        );

        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: engine_silo_to_silo_contract.address,
            input: contract_args,
        });

        let outcome = user_account
            .call(engine.inner.id(), "call")
            .args_borsh(call_args)
            .max_gas()
            .transact()
            .await
            .unwrap();

        let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
        if let TransactionStatus::Succeed(res) = result.status {
            let str_res = std::str::from_utf8(&res).unwrap();
            println!("{:?}", str_res);
            println!("{:?}", mock_token.id().to_string());
        }

        //
        let contract_args = engine_silo_to_silo_contract.create_call_method_bytes_with_args(
            "getNearAccountId",
            &[],
        );

        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: engine_silo_to_silo_contract.address,
            input: contract_args,
        });

        let outcome = user_account
            .call(engine.inner.id(), "call")
            .args_borsh(call_args)
            .max_gas()
            .transact()
            .await
            .unwrap();

        let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
        if let TransactionStatus::Succeed(res) = result.status {
            let str_res = std::str::from_utf8(&res).unwrap();
            println!("{:?}", str_res);
            println!("{:?}", engine_silo_to_silo_contract.address.encode());
        }

        let outcome = mock_token.call("storage_deposit")
            .args_json(serde_json::json!({
                "account_id": engine.inner.id().to_string()
            }))
            .max_gas()
            .deposit(1_250_000_000_000_000_000_000)
            .transact()
            .await
            .unwrap();

        println!("Storage deposit: {:?}", outcome);

        let outcome = mock_token.call("storage_deposit")
            .args_json(serde_json::json!({
                "account_id": silo.inner.id().to_string()
            }))
            .max_gas()
            .deposit(1_250_000_000_000_000_000_000)
            .transact()
            .await
            .unwrap();

        let mint_args = engine_mock_token.create_mint_call_bytes(user_address, U256::from(1000000000));
        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: engine_mock_token.address,
            input: mint_args.0,
        });

        let outcome = engine.inner.call("call")
            .args_borsh(call_args)
            .max_gas()
            .transact()
            .await
            .unwrap();
        println!("{:?}", outcome);

        let balance = engine.erc20_balance_of(&engine_mock_token, user_address).await.unwrap();
        println!("Balance MockTokens on Aurora: {:?}", balance.as_u64());


        // Approve proxy contract to spend user's wNEAR
        let evm_input = engine_mock_token
            .create_approve_call_bytes(engine_silo_to_silo_contract.address, U256::MAX);
        let result = engine
            .call_evm_contract_with(
                &user_account,
                engine_mock_token.address,
                evm_input,
                Wei::zero(),
            )
            .await
            .unwrap();
        aurora_engine::unwrap_success(result.status).unwrap();

        //
        let contract_args = engine_silo_to_silo_contract.create_call_method_bytes_with_args(
            "ftTransferCallToNear",
            &[
                ethabi::Token::Address(engine_mock_token.address.raw()),
                ethabi::Token::Uint(U256::from(100)),
                ethabi::Token::String( silo.inner.id().to_string()),
                ethabi::Token::String( user_address.encode())
            ],
        );

        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: engine_silo_to_silo_contract.address,
            input: contract_args,
        });

        let outcome = user_account
            .call(engine.inner.id(), "call")
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

        let balance = engine.erc20_balance_of(&engine_mock_token, user_address).await.unwrap();
        println!("Balance MockTokens on Aurora: {:?}", balance.as_u64());

        let balance = silo.erc20_balance_of(&silo_mock_token, user_address).await.unwrap();
        println!("Balance MockTokens on Silo: {:?}", balance.as_u64());
    }

    async fn deploy_silo_to_silo_sol_contract(
        engine: &AuroraEngine,
        user_account: &workspaces::Account,
        wnear_address: Address,
    ) -> DeployedContract {
        let contract_path = "../contracts";

        let aurora_sdk_path = Path::new("./aurora-solidity-sdk");
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
            &[format!(
                "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol:AuroraSdk:0x{}",
                aurora_sdk_lib.encode()
            ),
                format!(
                    "@auroraisnear/aurora-sdk/aurora-sdk/Utils.sol:Utils:0x{}",
                    utils_lib.encode()
                )
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
    ) -> workspaces::Contract {
        let contract_path = Path::new("./mock_token");
        let output = tokio::process::Command::new("cargo")
            .current_dir(contract_path)
            .env("RUSTFLAGS", "-C link-arg=-s")
            .args(["build", "--all", "--target", "wasm32-unknown-unknown", "--release"])
            .output()
            .await
            .unwrap();
        process::require_success(&output).unwrap();
        let artifact_path =
            contract_path.join("target/wasm32-unknown-unknown/release/mock_token.wasm");
        let wasm_bytes = tokio::fs::read(artifact_path).await.unwrap();
        worker.dev_deploy(&wasm_bytes).await.unwrap()
    }
}