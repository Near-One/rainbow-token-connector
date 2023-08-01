use std::process::Output;

pub fn require_success(output: &Output) -> Result<(), anyhow::Error> {
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow::Error::msg(format!("Command failed: {:?}", output)))
    }
}
