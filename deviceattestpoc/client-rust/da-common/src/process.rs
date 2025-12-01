//! Process utilities for device attestation tools.

use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::info;

/// Run another dar-* tool by name.
///
/// Searches for the tool in the same directory as the current executable,
/// falling back to /bin if not found.
///
/// # Exit codes
/// - Exit code 2 is propagated (pending approval status)
/// - Other non-zero exit codes result in an error
pub fn run_tool(name: &str) -> Result<()> {
    info!("Running: {}", name);

    // Try to find tool in same directory as current executable
    let tool_path = if let Ok(exe_path) = std::env::current_exe() {
        let dir = exe_path.parent().unwrap_or(std::path::Path::new("/bin"));
        let path = dir.join(name);
        if path.exists() {
            path
        } else {
            std::path::PathBuf::from(format!("/bin/{}", name))
        }
    } else {
        std::path::PathBuf::from(format!("/bin/{}", name))
    };

    let status = Command::new(&tool_path)
        .status()
        .with_context(|| format!("Failed to run {}", name))?;

    if !status.success() {
        if let Some(code) = status.code() {
            if code == 2 {
                // Pending approval - propagate
                std::process::exit(2);
            }
        }
        bail!("{} failed with status: {}", name, status);
    }

    Ok(())
}
