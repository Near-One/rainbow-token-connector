use crate::{
    aurora_engine::{erc20, erc20::ERC20DeployedAt, repo::AuroraEngineRepo},
    wnear::Wnear,
};
use aurora_engine_types::types::{Address, Wei};

#[tokio::test]
async fn test_compile_aurora_engine() {
    let contract = AuroraEngineRepo::download_and_compile_latest()
        .await
        .unwrap();
    assert!(!contract.is_empty());
}

#[tokio::test]
async fn test_deploy_aurora_engine() {
    let worker = workspaces::sandbox().await.unwrap();
    let engine = crate::aurora_engine::deploy_latest(&worker).await.unwrap();
    let address = Address::decode("000000000000000000000000000000000000000a").unwrap();
    let balance = Wei::new_u64(123456);
    engine.mint_account(address, 0, balance).await.unwrap();
    let view_balance = engine.get_balance(address).await.unwrap();
    assert_eq!(balance, view_balance);
}

#[tokio::test]
async fn test_deploy_erc20() {
    let worker = workspaces::sandbox().await.unwrap();
    let engine = crate::aurora_engine::deploy_latest(&worker).await.unwrap();
    let constructor = erc20::Constructor::load().await.unwrap();
    let address = engine
        .deploy_evm_contract(constructor.create_deploy_bytes("TEST", "AAA"))
        .await
        .unwrap();
    let erc20 = constructor.deployed_at(address);
    let mint_amount = 7654321.into();
    let recipient = Address::decode("000000000000000000000000000000000000000a").unwrap();
    let result = engine
        .call_evm_contract(
            address,
            erc20.create_mint_call_bytes(recipient, mint_amount),
            Wei::zero(),
        )
        .await
        .unwrap();
    crate::aurora_engine::unwrap_success(result.status).unwrap();
    let balance = engine.erc20_balance_of(&erc20, recipient).await.unwrap();
    assert_eq!(balance, mint_amount);
}

#[tokio::test]
async fn test_deploy_wnear() {
    let worker = workspaces::sandbox().await.unwrap();
    let engine = crate::aurora_engine::deploy_latest(&worker).await.unwrap();
    let wnear = Wnear::deploy(&worker, &engine).await.unwrap();

    // Try bridging some wnear into Aurora
    let deposit_amount = 100_567;
    let recipient = Address::decode("000000000000000000000000000000000000000a").unwrap();
    engine
        .mint_wnear(&wnear, recipient, deposit_amount)
        .await
        .unwrap();

    // Aurora Engine account owns the wnear tokens at the NEAR level
    let balance = wnear.ft_balance_of(engine.inner.id()).await.unwrap();
    assert_eq!(balance, deposit_amount);

    // Recipient address owns the tokens inside the EVM
    let balance = engine
        .erc20_balance_of(&wnear.aurora_token, recipient)
        .await
        .unwrap();
    assert_eq!(balance, deposit_amount.into());
}
