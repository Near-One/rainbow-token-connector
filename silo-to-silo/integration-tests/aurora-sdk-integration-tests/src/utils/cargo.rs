use crate::utils::process;
use std::path::Path;

const NO_SUCH_COMMAND: &str = "no such command";

/// Builds a Wasm artifcact for the Rust contract defined in the given directory.
/// This function uses the [cargo-near](https://github.com/near/cargo-near) too and
/// installs this extension if it is not already present. `cargo-near` only works with
/// contracts that use NEAR SDK version 4.1 or later.
pub async fn build_contract<P: AsRef<Path>>(contract_dir: P) -> anyhow::Result<Vec<u8>> {
    let contract_path = contract_dir.as_ref();
    check_cargo_near(contract_path).await?;

    let output = tokio::process::Command::new("cargo")
        .current_dir(contract_path)
        .args(["near", "build", "--no-abi"])
        .output()
        .await?;
    process::require_success(&output)?;

    let output_text = String::from_utf8_lossy(&output.stderr);
    let output_lines = output_text.split('\n').map(|line| line.trim());
    let mut binary_path = None;
    for line in output_lines {
        if line.contains("Binary:") {
            binary_path = Some(line.split_once(": ").unwrap().1);
        }
    }

    if binary_path.is_none() {
        return Err(anyhow::Error::msg("Failed to parse cargo-near output"));
    }

    // Unwrap is safe by check above
    let bytes = tokio::fs::read(binary_path.unwrap()).await.map_err(|e| {
        let x: anyhow::Error = e.into();
        x.context(format!("Trying to read file: {binary_path:?}"))
    })?;

    Ok(bytes)
}

async fn check_cargo_near(contract_path: &Path) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("cargo")
        .current_dir(contract_path)
        .args(["near", "--version"])
        .output()
        .await?;

    if !output.status.success()
        || contains_error_msg(&output.stderr)
        || contains_error_msg(&output.stdout)
    {
        let output = tokio::process::Command::new("cargo")
            .current_dir(contract_path)
            .args(["install", "cargo-near"])
            .output()
            .await?;
        return process::require_success(&output);
    }

    Ok(())
}

fn contains_error_msg(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).contains(NO_SUCH_COMMAND)
}
