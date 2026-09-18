use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

mod lab;
mod verify;

const HELP: &str = "OpenConnect GUI build tasks

  cargo xtask native build --target host|TRIPLE [--dependency-prefix PATH]
  cargo xtask build --target host|TRIPLE [--dependency-prefix PATH]
  cargo xtask build --target host|TRIPLE --headless
  cargo xtask package --target host|TRIPLE [--headless] [--dependency-prefix PATH]
  cargo xtask lab up|down [--target host|TRIPLE]
  cargo xtask verify tunnel --profile NAME [--target host|TRIPLE]
  cargo xtask verify protocols
  cargo xtask verify browser

Native builds require Python 3.10+ with the tarfile security backport and the
platform native toolchain. Native/build commands discover /opt/ocvpn-deps or
Linux distro dependencies, Homebrew on macOS, or an explicit dependency prefix.
Package builds on macOS/Windows build checksum-pinned dependency sources when
no prefix is supplied. Windows requires MSYS2 MinGW-w64 and MSVC Rust.
Build/package run locked release Cargo builds; desktop builds also generate
model bindings and run npm ci/build. --headless excludes desktop prerequisites.
Commands run on the matching native runner only.
";

enum Task {
    Native,
    Build,
    Package,
    VerifyProtocols,
    VerifyBrowser,
    LabUp,
    LabDown,
    VerifyTunnel,
}

struct Options {
    task: Task,
    target: String,
    dependency_prefix: Option<PathBuf>,
    headless: bool,
    profile: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let Some(options) = parse(env::args_os().skip(1).collect())? else {
        print!("{HELP}");
        return Ok(());
    };
    let root = dunce::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("xtask manifest has no repository parent")?,
    )
    .map_err(|error| format!("cannot locate repository root: {error}"))?;
    if !root.join("Cargo.toml").is_file() || !root.join("native/build.py").is_file() {
        return Err(format!(
            "repository build inputs are missing under {}",
            root.display()
        ));
    }
    let host = rust_host(&root)?;
    let target = if options.target == "host" {
        &host
    } else {
        &options.target
    };
    const TARGETS: &[&str] = &[
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ];
    if !TARGETS.contains(&target.as_str()) {
        return Err(format!(
            "unsupported native target {target}; supported targets: {}",
            TARGETS.join(", ")
        ));
    }
    if target != &host {
        return Err(format!(
            "target {target} requires its matching native runner; this Rust host is {host}. Cross-target native builds are not supported"
        ));
    }
    match options.task {
        Task::VerifyProtocols => return verify::protocols(&root, target),
        Task::VerifyBrowser => return verify::browser(&root, target),
        Task::LabUp => return lab::up(&root, target),
        Task::LabDown => return lab::down(&root, target),
        Task::VerifyTunnel => {
            return lab::verify(
                &root,
                target,
                options
                    .profile
                    .as_deref()
                    .ok_or("verify tunnel requires --profile NAME")?,
            );
        }
        _ => {}
    }
    let mut dependency_prefix = options.dependency_prefix;
    let mut dependency_sources = None;
    if matches!(options.task, Task::Package)
        && dependency_prefix.is_none()
        && (target.contains("apple") || target.contains("windows"))
    {
        checked(
            Command::new("python3")
                .current_dir(&root)
                .arg(root.join("native/build-dependencies.py"))
                .args(["--target", target]),
            "pinned native dependency source build",
        )?;
        let dependencies = root.join("target/dependencies").join(target);
        dependency_prefix = Some(dependencies.join("prefix"));
        dependency_sources = Some(dependencies.join("sources"));
    }
    let mut native = Command::new("python3");
    native
        .current_dir(&root)
        .arg(root.join("native/build.py"))
        .args(["--target", target]);
    if target.contains("apple") {
        native.env("MACOSX_DEPLOYMENT_TARGET", "13.0");
    }
    if matches!(options.task, Task::Package) && env::var_os("CFLAGS").is_none() {
        native.env("CFLAGS", "-O2");
    }
    if let Some(path) = dependency_prefix {
        let prefix = dunce::canonicalize(&path).map_err(|error| {
            format!("cannot open dependency prefix {}: {error}; provide an existing native dependency directory", path.display())
        })?;
        if !prefix.is_dir() {
            return Err(format!(
                "dependency prefix {} is not a directory",
                prefix.display()
            ));
        }
        native.arg("--dependency-prefix").arg(prefix);
    }
    checked(
        &mut native,
        "native build (install Python 3.10+ with the tarfile security backport and the target native toolchain; Windows requires MSYS2 Python)",
    )?;
    if matches!(options.task, Task::Build | Task::Package) {
        let desktop = root.join("apps/desktop");
        if !options.headless {
            checked(
                npm_command(&desktop)?.arg("ci"),
                "locked frontend dependency installation (install Node.js and npm as specified in apps/desktop/package.json)",
            )?;
            checked(
                Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
                    .current_dir(&root)
                    .args([
                        "run",
                        "--locked",
                        "-p",
                        "ocvpn-model",
                        "--example",
                        "export_types",
                    ]),
                "canonical model TypeScript export",
            )?;
            checked(
                npm_command(&desktop)?.args(["run", "build"]),
                "frontend production build",
            )?;
        }
        let mut cargo = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        if env::var_os("RUSTFLAGS").is_none() && env::var_os("CARGO_ENCODED_RUSTFLAGS").is_none() {
            cargo.env(
                "CARGO_ENCODED_RUSTFLAGS",
                format!(
                    "--remap-path-prefix={}=/usr/src/openconnect-gui",
                    root.display()
                ),
            );
        }
        cargo
            .current_dir(&root)
            .args(["build", "--release", "--locked", "--target", target]);
        if options.headless {
            cargo.args(["-p", "ocvpn-cli", "-p", "ocvpn-service", "-p", "ocvpn-net"]);
        } else {
            cargo.args(["--workspace", "--features", "ocvpn-desktop/custom-protocol"]);
        }
        if target.contains("apple") {
            cargo.env("MACOSX_DEPLOYMENT_TARGET", "13.0");
        }
        checked(
            &mut cargo,
            "Rust workspace release build (install the matching Rust and platform desktop prerequisites)",
        )?;
    }
    if matches!(options.task, Task::Package) {
        let mut package = Command::new("python3");
        if env::var_os("RUSTFLAGS").is_none() && env::var_os("CARGO_ENCODED_RUSTFLAGS").is_none() {
            package.env(
                "CARGO_ENCODED_RUSTFLAGS",
                format!(
                    "--remap-path-prefix={}=/usr/src/openconnect-gui",
                    root.display()
                ),
            );
        }
        package
            .current_dir(&root)
            .arg(root.join("packaging/package.py"))
            .args(["--target", target]);
        if let Some(sources) = dependency_sources {
            package.env("OCVPN_DEPENDENCY_SOURCES", sources);
        }
        if options.headless {
            package.arg("--headless");
        }
        checked(
            &mut package,
            "native installer, standalone CLI/TUI and source packaging",
        )?;
    }
    Ok(())
}

fn parse(args: Vec<OsString>) -> Result<Option<Options>, String> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        return Ok(None);
    }
    let (task, start) = match args.first().and_then(|arg| arg.to_str()) {
        Some("build") => (Task::Build, 1),
        Some("package") => (Task::Package, 1),
        Some("lab") if args.get(1).is_some_and(|arg| arg == "up") => (Task::LabUp, 2),
        Some("lab") if args.get(1).is_some_and(|arg| arg == "down") => (Task::LabDown, 2),
        Some("verify") if args.get(1).is_some_and(|arg| arg == "tunnel") => (Task::VerifyTunnel, 2),
        Some("native") if args.get(1).is_some_and(|arg| arg == "build") => (Task::Native, 2),
        Some("verify") if args.get(1).is_some_and(|arg| arg == "protocols") => {
            (Task::VerifyProtocols, 2)
        }
        Some("verify") if args.get(1).is_some_and(|arg| arg == "browser") => {
            (Task::VerifyBrowser, 2)
        }
        _ => return Err(format!("unknown task\n\n{HELP}")),
    };
    let mut target = None;
    let mut dependency_prefix = None;
    let mut headless = false;
    let mut profile = None;
    let mut index = start;
    while index < args.len() {
        let flag = &args[index];
        if flag == "--headless" && matches!(task, Task::Build | Task::Package) && !headless {
            headless = true;
            index += 1;
            continue;
        }
        if flag != "--target" && flag != "--dependency-prefix" && flag != "--profile" {
            return Err(format!("unknown option {flag:?}\n\n{HELP}"));
        }
        let value = args
            .get(index + 1)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("option {flag:?} requires a value"))?;
        if flag == "--target" {
            if target.is_some() {
                return Err("--target may only be specified once".into());
            }
            target = Some(
                value
                    .to_str()
                    .ok_or("target must be a UTF-8 Rust target triple")?
                    .to_owned(),
            );
        } else if flag == "--profile" {
            if !matches!(task, Task::VerifyTunnel) || profile.is_some() {
                return Err("--profile applies once to verify tunnel".into());
            }
            profile = Some(value.to_str().ok_or("profile must be UTF-8")?.to_owned());
        } else {
            if dependency_prefix.is_some() {
                return Err("--dependency-prefix may only be specified once".into());
            }
            dependency_prefix = Some(PathBuf::from(value));
        }
        index += 2;
    }
    if matches!(
        task,
        Task::VerifyProtocols
            | Task::VerifyBrowser
            | Task::LabUp
            | Task::LabDown
            | Task::VerifyTunnel
    ) {
        if dependency_prefix.is_some() {
            return Err("--dependency-prefix applies only to native builds".into());
        }
        target.get_or_insert_with(|| "host".into());
    }
    Ok(Some(Options {
        task,
        target: target.ok_or("missing --target host|TRIPLE")?,
        dependency_prefix,
        headless,
        profile,
    }))
}

fn rust_host(root: &Path) -> Result<String, String> {
    let output = Command::new("rustc")
        .arg("-vV")
        .current_dir(root)
        .output()
        .map_err(|error| {
            format!("cannot run rustc -vV: {error}; install the pinned Rust toolchain")
        })?;
    if !output.status.success() {
        return Err(format!(
            "rustc -vV failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let version =
        std::str::from_utf8(&output.stdout).map_err(|_| "rustc -vV returned invalid UTF-8")?;
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV did not report a host triple".into())
}

fn checked(command: &mut Command, step: &str) -> Result<(), String> {
    eprintln!("xtask: {step}");
    let status = command.status().map_err(|error| {
        format!(
            "could not launch {} for {step}: {error}",
            command.get_program().to_string_lossy()
        )
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{step} failed ({status}); see tool output above"))
    }
}

fn npm_command(directory: &Path) -> Result<Command, String> {
    // Execute npm's JavaScript entrypoint directly on Windows rather than a
    // cmd.exe command string or a batch shim. Node installations ship both.
    let mut command = if cfg!(windows) {
        let path = env::var_os("PATH").ok_or("PATH is absent; install Node.js and npm")?;
        let cli = env::split_paths(&path)
            .map(|directory| directory.join("node_modules/npm/bin/npm-cli.js"))
            .find(|candidate| candidate.is_file())
            .ok_or("cannot locate node_modules/npm/bin/npm-cli.js on PATH; install Node.js with npm and add its directory to PATH")?;
        let mut command = Command::new("node");
        command.arg(cli);
        command
    } else {
        Command::new(OsStr::new("npm"))
    };
    command.current_dir(directory);
    Ok(command)
}
