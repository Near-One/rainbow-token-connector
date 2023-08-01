use crate::utils::{git::Git, process};
use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
};
use tokio::sync::Mutex;

pub const LATEST_ENGINE_VERSION: &str = "2.9.1";
const TARGET: &str = "target";
const ENGINE_PATH: &str = "aurora-engine";
/// A lock to prevent multiple tests from modifying the aurora-engine repo at the same time.
static ENGINE_LOCK: Mutex<()> = Mutex::const_new(());

pub struct AuroraEngineRepo;

pub struct AuroraEngineRepoActions<T> {
    output_type: PhantomData<T>,
    actions: Vec<Action>,
}

#[derive(Debug)]
pub enum ActionOutput {
    Unit,
    Bytes(Vec<u8>),
}

impl AuroraEngineRepo {
    pub async fn download_and_compile_latest() -> anyhow::Result<Vec<u8>> {
        Self::download()
            .checkout(LATEST_ENGINE_VERSION)
            .compile_engine_contract()
            .execute()
            .await
    }

    pub fn download() -> AuroraEngineRepoActions<()> {
        AuroraEngineRepoActions {
            output_type: Default::default(),
            actions: vec![Action::Download],
        }
    }
}

impl<T> AuroraEngineRepoActions<T> {
    pub fn checkout(self, version: &str) -> AuroraEngineRepoActions<()> {
        let mut current_actions = self.actions;
        current_actions.push(Action::Checkout {
            version: version.into(),
        });
        AuroraEngineRepoActions {
            output_type: Default::default(),
            actions: current_actions,
        }
    }

    pub fn compile_engine_contract(self) -> AuroraEngineRepoActions<Vec<u8>> {
        let mut current_actions = self.actions;
        current_actions.push(Action::CompileEngine);
        AuroraEngineRepoActions {
            output_type: Default::default(),
            actions: current_actions,
        }
    }

    pub fn compile_xcc_router_contract(self) -> AuroraEngineRepoActions<Vec<u8>> {
        let mut current_actions = self.actions;
        current_actions.push(Action::CompileXccRouter);
        AuroraEngineRepoActions {
            output_type: Default::default(),
            actions: current_actions,
        }
    }
}

impl<T: TryFrom<ActionOutput, Error = anyhow::Error>> AuroraEngineRepoActions<T> {
    pub async fn execute(self) -> anyhow::Result<T> {
        let _guard = ENGINE_LOCK.lock().await;
        let engine_path = find_target_dir()?.join(ENGINE_PATH);
        let mut output = ActionOutput::Unit;
        for action in self.actions {
            output = action.execute(&engine_path).await?;
        }
        output.try_into()
    }
}

enum Action {
    Download,
    Checkout { version: String },
    CompileEngine,
    CompileXccRouter,
}

impl Action {
    async fn execute(self, engine_path: &Path) -> anyhow::Result<ActionOutput> {
        match self {
            Self::Download => {
                if !engine_path.exists() {
                    let target_dir = engine_path.parent().unwrap().canonicalize()?;
                    let git = Git::in_working_dir(target_dir);
                    git.clone("https://github.com/aurora-is-near/aurora-engine.git")
                        .await?;
                }
                Ok(ActionOutput::Unit)
            }
            Self::Checkout { version } => {
                let git = Git::in_working_dir(engine_path);
                git.fetch("origin").await?;
                git.checkout(&version).await?;
                Ok(ActionOutput::Unit)
            }
            Self::CompileEngine => {
                // For some reason `cargo` does not automatically pick up the toolchain file
                // in the aurora-engine directory, so we manually read it and set the `RUSTUP_TOOLCHAIN`
                // environment variable instead.
                let toolchain = read_toolchain(engine_path).await?;
                add_wasm_target(engine_path, &toolchain).await?;
                let output = tokio::process::Command::new("cargo")
                    .env("RUSTUP_TOOLCHAIN", &toolchain)
                    .current_dir(engine_path)
                    .args([
                        "build",
                        "--target",
                        "wasm32-unknown-unknown",
                        "--release",
                        "--no-default-features",
                        "--features=mainnet,integration-test",
                        "-p",
                        "aurora-engine",
                        "-Z",
                        "avoid-dev-deps",
                    ])
                    .output()
                    .await?;
                process::require_success(&output)?;
                let binary_path = engine_path.join(
                    [
                        "target",
                        "wasm32-unknown-unknown",
                        "release",
                        "aurora_engine.wasm",
                    ]
                    .iter()
                    .collect::<PathBuf>(),
                );
                let bytes = tokio::fs::read(binary_path).await?;
                Ok(ActionOutput::Bytes(bytes))
            }
            Self::CompileXccRouter => {
                let toolchain = read_toolchain(engine_path).await?;
                add_wasm_target(engine_path, &toolchain).await?;
                let router_path = engine_path.join("etc").join("xcc-router");
                let output = tokio::process::Command::new("cargo")
                    .env("RUSTUP_TOOLCHAIN", &toolchain)
                    .env("RUSTFLAGS", "-C link-arg=-s")
                    .current_dir(&router_path)
                    .args(["build", "--target", "wasm32-unknown-unknown", "--release"])
                    .output()
                    .await?;
                process::require_success(&output)?;
                let binary_path = router_path.join(
                    [
                        "target",
                        "wasm32-unknown-unknown",
                        "release",
                        "xcc_router.wasm",
                    ]
                    .iter()
                    .collect::<PathBuf>(),
                );
                let bytes = tokio::fs::read(binary_path).await?;
                Ok(ActionOutput::Bytes(bytes))
            }
        }
    }
}

async fn read_toolchain(engine_path: &Path) -> anyhow::Result<String> {
    let bytes = tokio::fs::read(engine_path.join("rust-toolchain")).await?;
    let value: toml::Value = toml::from_slice(&bytes)?;
    let result = value
        .as_table()
        .and_then(|t| t.get("toolchain"))
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("channel"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::Error::msg("Failed to parse rust-toolchain toml"))?
        .to_string();
    Ok(result)
}

async fn add_wasm_target(engine_path: &Path, toolchain: &str) -> anyhow::Result<()> {
    let output = tokio::process::Command::new("rustup")
        .env("RUSTUP_TOOLCHAIN", toolchain)
        .current_dir(engine_path)
        .args(["target", "add", "wasm32-unknown-unknown"])
        .output()
        .await?;
    process::require_success(&output)?;
    Ok(())
}

/// Recursively moves up the path tree, starting with the current directory, to find a `target`
/// directory.
fn find_target_dir() -> anyhow::Result<PathBuf> {
    let pwd = Path::new(".").canonicalize()?;
    let mut current_base = pwd.as_path();
    let mut result = current_base.join(TARGET);
    while !result.exists() {
        if let Some(p) = current_base.parent() {
            current_base = p;
        } else {
            return Err(anyhow::Error::msg("Failed to find target directory"));
        }
        result = current_base.join(TARGET);
    }
    Ok(result)
}

impl TryFrom<ActionOutput> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(value: ActionOutput) -> Result<Self, Self::Error> {
        match value {
            ActionOutput::Bytes(bytes) => Ok(bytes),
            other => Err(anyhow::Error::msg(format!(
                "Expected Bytes output, got {:?}",
                other
            ))),
        }
    }
}

impl TryFrom<ActionOutput> for () {
    type Error = anyhow::Error;

    fn try_from(value: ActionOutput) -> Result<Self, Self::Error> {
        match value {
            ActionOutput::Unit => Ok(()),
            other => Err(anyhow::Error::msg(format!(
                "Expected Unit output, got {:?}",
                other
            ))),
        }
    }
}

#[test]
fn test_find_target_dir() {
    let result = find_target_dir().unwrap();
    assert_eq!(
        result,
        Path::new("../").canonicalize().unwrap().join(TARGET)
    );
}
