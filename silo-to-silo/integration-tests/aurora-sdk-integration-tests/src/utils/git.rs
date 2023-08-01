use crate::utils::process;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct Git {
    working_dir: PathBuf,
}

impl Git {
    pub fn new() -> Self {
        Self {
            working_dir: Path::new(".").into(),
        }
    }

    pub fn in_working_dir<P: AsRef<Path>>(path: P) -> Self {
        Self {
            working_dir: path.as_ref().into(),
        }
    }

    pub async fn clone(&self, url: &str) -> anyhow::Result<()> {
        let output = self.git_command().args(["clone", url]).output().await?;
        process::require_success(&output)?;
        Ok(())
    }

    pub async fn checkout(&self, tag: &str) -> anyhow::Result<()> {
        let output = self.git_command().args(["checkout", tag]).output().await?;
        process::require_success(&output)?;
        Ok(())
    }

    pub async fn fetch(&self, remote: &str) -> anyhow::Result<()> {
        let output = self.git_command().args(["fetch", remote]).output().await?;
        process::require_success(&output)?;
        Ok(())
    }

    fn git_command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.working_dir);
        cmd
    }
}

impl Default for Git {
    fn default() -> Self {
        Self::new()
    }
}
