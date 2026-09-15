use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use super::checked;

fn prepare(root: &Path, target: &str, desktop: bool) -> Result<(PathBuf, PathBuf), String> {
    let native = root
        .join("target/native")
        .join(target)
        .join("stage/ocvpn-native");
    if !native.is_dir() {
        return Err(
            "Bundled native stage is missing; run cargo xtask native build --target host first"
                .into(),
        );
    }
    let venv = root.join("target/fixture-venv");
    let python = venv.join(if cfg!(windows) {
        "Scripts/python.exe"
    } else {
        "bin/python"
    });
    if !python.is_file() {
        checked(
            Command::new(if cfg!(windows) { "python" } else { "python3" })
                .current_dir(root)
                .args(["-m", "venv"])
                .arg(&venv),
            "isolated protocol fixture Python environment (requires Python 3 and venv)",
        )?;
    }
    checked(
        Command::new(&python)
            .current_dir(root)
            .args([
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--requirement",
            ])
            .arg(root.join("native/fixtures/requirements.txt")),
        "pinned development-only fixture dependencies",
    )?;
    let mut build = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    build
        .current_dir(root)
        .args([
            "build",
            "--locked",
            "-p",
            "ocvpn-engine",
            "-p",
            "ocvpn-client",
            "--features",
            "ocvpn-client/development",
            "--examples",
            "--target-dir",
        ])
        .arg(root.join("target"));
    if desktop {
        build.args(["-p", "ocvpn-desktop", "--bins"]);
    }
    checked(
        &mut build,
        "real native discovery and shared-client authentication drivers",
    )?;
    Ok((native, python))
}

pub(super) fn protocols(root: &Path, target: &str) -> Result<(), String> {
    let (native, python) = prepare(root, target, false)?;
    let examples = root.join("target/debug/examples");
    let discovery = examples.join(format!("discover{}", env::consts::EXE_SUFFIX));
    let driver = examples.join(format!("auth_fixture{}", env::consts::EXE_SUFFIX));
    checked(
        Command::new(discovery).current_dir(root).arg(&native),
        "actual bundled protocol and HPKE discovery",
    )?;
    for script in [
        "verify_policy.py",
        "verify_protocols.py",
        "verify_hotp.py",
        "verify_browser_chain.py",
    ] {
        checked(
            Command::new(&python)
                .current_dir(root)
                .arg(root.join("native/fixtures").join(script))
                .arg("--native-root")
                .arg(&native)
                .arg("--driver")
                .arg(&driver)
                .arg("--python")
                .arg(&python),
            script,
        )?;
    }
    Ok(())
}

pub(super) fn browser(root: &Path, target: &str) -> Result<(), String> {
    let (native, python) = prepare(root, target, true)?;
    let debug = root.join("target/debug");
    let mut command = Command::new(&python);
    command
        .current_dir(root)
        .arg(root.join("native/fixtures/verify_browser.py"))
        .arg("--native-root")
        .arg(native)
        .arg("--driver")
        .arg(
            debug
                .join("examples")
                .join(format!("browser_fixture{}", env::consts::EXE_SUFFIX)),
        )
        .arg("--gui")
        .arg(debug.join(format!("ocvpn-gui{}", env::consts::EXE_SUFFIX)))
        .arg("--peer")
        .arg(
            debug
                .join("examples")
                .join(format!("browser_peer_fixture{}", env::consts::EXE_SUFFIX)),
        )
        .arg("--python")
        .arg(&python)
        .arg("--evidence")
        .arg(root.join("target/browser-verification"));
    if !cfg!(target_os = "linux") {
        command.arg("--interactive");
    }
    checked(
        &mut command,
        "actual native SAML webviews, independent accounts and unrelated-origin isolation",
    )
}
