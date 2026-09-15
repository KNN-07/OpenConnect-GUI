use std::{path::Path, process::Command};

fn run(root: &Path, target: &str, action: &str, profile: Option<&str>) -> Result<(), String> {
    let python = if cfg!(windows) { "python" } else { "python3" };
    let mut command = Command::new(python);
    command
        .current_dir(root)
        .arg(root.join("native/lab/lab.py"))
        .args([action, "--target", target]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    let status = command
        .status()
        .map_err(|error| format!("cannot launch lab harness (Python 3.10+ required): {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "lab {action} failed; no tunnel or platform success is implied (exit {status})"
        ))
    }
}

pub(super) fn up(root: &Path, target: &str) -> Result<(), String> {
    run(root, target, "up", None)
}
pub(super) fn down(root: &Path, target: &str) -> Result<(), String> {
    run(root, target, "down", None)
}
pub(super) fn verify(root: &Path, target: &str, profile: &str) -> Result<(), String> {
    run(root, target, "verify", Some(profile))
}
