use crate::{
    aurora_engine::AuroraEngine,
    utils::{ethabi::ContractConstructor, process},
};
use aurora_engine_types::types::Address;
use std::path::{Path, PathBuf};
use tokio::{process::Command, sync::Mutex};

/// A lock to prevent multiple tests from compiling the Solidity contracts with different
/// library addresses at the same time.
static FORGE_LOCK: Mutex<()> = Mutex::const_new(());

pub async fn deploy_codec_lib<P: AsRef<Path>>(
    aurora_sdk_path: P,
    engine: &AuroraEngine,
) -> anyhow::Result<Address> {
    let codec = forge_build(aurora_sdk_path, &[], &["out", "Codec.sol", "Codec.json"]).await?;
    let address = engine.deploy_evm_contract(codec.code).await?;
    Ok(address)
}

pub async fn deploy_utils_lib<P: AsRef<Path>>(
    aurora_sdk_path: P,
    engine: &AuroraEngine,
) -> anyhow::Result<Address> {
    let utils = forge_build(aurora_sdk_path, &[], &["out", "Utils.sol", "Utils.json"]).await?;
    let address = engine.deploy_evm_contract(utils.code).await?;
    Ok(address)
}

pub async fn deploy_aurora_sdk_lib<P: AsRef<Path>>(
    aurora_sdk_path: P,
    engine: &AuroraEngine,
    codec_lib: Address,
    utils_lib: Address,
) -> anyhow::Result<Address> {
    let aurora_sdk = forge_build(
        aurora_sdk_path,
        &[
            format!("src/Codec.sol:Codec:0x{}", codec_lib.encode()),
            format!("src/Utils.sol:Utils:0x{}", utils_lib.encode()),
        ],
        &["out", "AuroraSdk.sol", "AuroraSdk.json"],
    )
    .await?;

    let address = engine.deploy_evm_contract(aurora_sdk.code).await?;
    Ok(address)
}

pub async fn forge_build<P: AsRef<Path>>(
    root_path: P,
    libraries: &[String],
    contract_output_path: &[&str],
) -> anyhow::Result<ContractConstructor> {
    let _guard = FORGE_LOCK.lock().await;
    let contracts_path = root_path.as_ref();
    let args = std::iter::once("build").chain(libraries.iter().flat_map(|x| ["--libraries", x]));
    let output = Command::new("forge")
        .current_dir(contracts_path)
        .args(args)
        .output()
        .await?;
    process::require_success(&output)?;

    let s = tokio::fs::read_to_string(
        contracts_path.join(contract_output_path.iter().collect::<PathBuf>()),
    )
    .await?;

    let result: serde_json::Value = serde_json::from_str(&s)?;

    let code_hex =
        json_lens(&result, &["bytecode", "object"], |x| x.as_str()).ok_or_else(forge_parse_err)?;
    let code_hex = code_hex.strip_prefix("0x").unwrap_or(code_hex);
    let code = hex::decode(code_hex)?;

    let abi_data = json_lens(&result, &["abi"], Some).ok_or_else(forge_parse_err)?;
    let abi = serde_json::from_value(abi_data.clone())?;

    Ok(ContractConstructor { code, abi })
}

fn json_lens<'a, T, F>(value: &'a serde_json::Value, keys: &[&str], interp: F) -> Option<T>
where
    F: FnOnce(&'a serde_json::Value) -> Option<T>,
{
    let mut value = value;
    for k in keys {
        value = value.as_object()?.get(*k)?;
    }
    interp(value)
}

fn forge_parse_err() -> anyhow::Error {
    anyhow::Error::msg("Failed to parse Forge output")
}
