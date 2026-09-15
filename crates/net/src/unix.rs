//! Journal-aware mutation sites for the executed pinned Unix vpnc lifecycle.
//! The shell requests only typed preflighted operations over private pipes.
use crate::journal::{Key, Mutation};
use ocvpn_model::{Error, ErrorCode, NetworkConfig, NetworkObservation, NetworkReason, Result};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::{Component, Path},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
mod lifecycle;
#[cfg(target_os = "linux")]
#[path = "unix/linux.rs"]
mod native;
#[cfg(target_os = "macos")]
#[path = "unix/macos.rs"]
mod native;

const LIMIT: usize = 1024 * 1024;
const SCRIPT: &[u8] = include_bytes!("../../../packaging/common/vpnc-script");
#[cfg(target_os = "linux")]
const SCRIPT_PATH: &str = "/usr/libexec/openconnect-gui/vpnc-script";
#[cfg(target_os = "macos")]
const SCRIPT_PATH: &str = "/Applications/OpenConnect GUI.app/Contents/Resources/vpnc-script";

thread_local! { static APPLY_DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) }; }
struct DeadlineGuard(Option<Instant>);
impl DeadlineGuard {
    fn new(duration: Duration) -> Self {
        let until = Instant::now() + duration;
        let previous = APPLY_DEADLINE
            .with(|slot| slot.replace(Some(slot.get().map_or(until, |old| old.min(until)))));
        Self(previous)
    }
}
impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        APPLY_DEADLINE.with(|slot| slot.set(self.0));
    }
}

fn failure(message: &'static str) -> Error {
    Error::new(ErrorCode::NetworkFailure, message)
}
fn text(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| failure("Invalid Unix journal string"))
}
fn strings(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| failure("Invalid Unix journal list"))?
        .iter()
        .map(|v| text(v).map(str::to_owned))
        .collect()
}
fn safe_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        || name.starts_with('-')
    {
        return Err(Error::invalid("Unsafe native network identifier"));
    }
    Ok(())
}
fn trusted_script() -> Result<File> {
    // Walk using directory descriptors. No ancestor can be exchanged for a
    // symlink between the ownership check and opening the next component.
    let mut directory = File::open("/").map_err(|_| failure("Cannot open filesystem root"))?;
    let components: Vec<_> = Path::new(SCRIPT_PATH)
        .components()
        .filter_map(|c| {
            if let Component::Normal(c) = c {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    for (i, component) in components.iter().enumerate() {
        use std::os::unix::ffi::OsStrExt;
        let component = std::ffi::CString::new(component.as_bytes())
            .map_err(|_| failure("Invalid installed script path"))?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if i + 1 < components.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            return Err(failure(
                "Installed vpnc-script path is missing or contains a symlink",
            ));
        }
        let next = unsafe { File::from_raw_fd(fd) };
        let metadata = next
            .metadata()
            .map_err(|_| failure("Cannot inspect installed vpnc-script"))?;
        // /Applications is normally root:admin 0775. Ancestor group writes
        // cannot substitute executable content: every component is opened
        // nofollow, the final inode is root-only writable, its bytes must match
        // the embedded asset, and execution uses this already-open descriptor.
        let final_component = i + 1 == components.len();
        let forbidden_writes = if final_component { 0o022 } else { 0o002 };
        if metadata.uid() != 0
            || metadata.mode() & forbidden_writes != 0
            || (final_component && !metadata.is_file())
        {
            return Err(failure(
                "Installed vpnc-script must be administrator-owned and nonwritable",
            ));
        }
        directory = next;
    }
    let mut bytes = Vec::new();
    (&directory)
        .take((SCRIPT.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("Cannot read installed vpnc-script"))?;
    if bytes != SCRIPT {
        return Err(failure(
            "Installed vpnc-script does not match the reviewed pinned asset",
        ));
    }
    Ok(directory)
}

/// All commands have fixed installed paths, a clean environment, bounded input,
/// bounded output and a deadline. Children stay in the worker's supervised
/// process group; the service kills and waits for that group before recovery.
fn command(
    program: &str,
    arguments: &[String],
    input: Option<&str>,
    mutate: bool,
) -> Result<std::process::Output> {
    let until = Instant::now() + Duration::from_secs(15);
    let deadline = APPLY_DEADLINE.with(|slot| slot.get().map_or(until, |outer| outer.min(until)));
    if Instant::now() >= deadline {
        return Err(failure("Network transaction deadline exceeded"));
    }
    if input.is_some_and(|s| s.len() > LIMIT)
        || arguments.len() > 2048
        || arguments
            .iter()
            .any(|s| s.len() > 65536 || s.contains('\0'))
    {
        return Err(failure("Native network command exceeds limits"));
    }
    let operation = match program {
        "/usr/sbin/ip" => "ocgui-ip",
        "/sbin/ip" => "ocgui-ip-sbin",
        "/sbin/ifconfig" => "ocgui-ifconfig",
        "/sbin/route" => "ocgui-route",
        "/usr/bin/resolvectl" => "ocgui-resolvectl",
        "/sbin/resolvconf" => "ocgui-resolvconf",
        "/usr/sbin/scutil" => "ocgui-scutil",
        "/ocgui/addrgen" if mutate => "ocgui-addrgen",
        "/usr/sbin/netstat" if !mutate => "",
        _ => return Err(failure("Native network tool is not allowlisted")),
    };
    let script = if mutate {
        Some(trusted_script()?)
    } else {
        None
    };
    let mut child = if script.is_some() {
        Command::new("/bin/sh")
    } else {
        Command::new(program)
    };
    child
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C");
    if script.is_some() {
        child.arg("/dev/fd/3").arg(operation);
    }
    child
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let fd = script.as_ref().map(AsRawFd::as_raw_fd);
    #[cfg(target_os = "linux")]
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        child.pre_exec(move || {
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                || libc::getppid() != parent_pid
            {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(fd) = fd {
                if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::lseek(3, 0, libc::SEEK_SET) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = child
        .spawn()
        .map_err(|_| failure("Cannot launch installed native network tool"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| failure("Cannot open native tool input"))?;
    let input = input.unwrap_or("").as_bytes().to_vec();
    let writer = thread::spawn(move || stdin.write_all(&input));
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure("Cannot open native tool output"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| failure("Cannot open native tool diagnostics"))?;
    let out = thread::spawn(move || {
        let mut b = Vec::new();
        stdout
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut b)
            .map(|_| b)
    });
    let err = thread::spawn(move || {
        let mut b = Vec::new();
        stderr
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut b)
            .map(|_| b)
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => break None,
        }
    };
    if status.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    while !(out.is_finished() && err.is_finished() && writer.is_finished()) {
        if Instant::now() >= deadline {
            // Never wait forever on descendants retaining pipe descriptors.
            // Returning failure causes the supervisor to cancel the inherited
            // worker group; process exit releases these detached reader threads.
            return Err(failure(
                "Native network command retained pipes beyond its deadline",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = out
        .join()
        .map_err(|_| failure("Native tool output reader failed"))?
        .map_err(|_| failure("Cannot read native tool output"))?;
    let diagnostics = err
        .join()
        .map_err(|_| failure("Native tool diagnostic reader failed"))?
        .map_err(|_| failure("Cannot read native tool diagnostics"))?;
    let written = writer
        .join()
        .map_err(|_| failure("Native tool input writer failed"))?;
    if output.len() > LIMIT || diagnostics.len() > LIMIT {
        return Err(failure("Native network command exceeded output limit"));
    }
    let status = status.ok_or_else(|| failure("Native network command timed out"))?;
    if written.is_err() {
        return Err(failure("Cannot write native network command input"));
    }
    Ok(std::process::Output {
        status,
        stdout: output,
        stderr: diagnostics,
    })
}
fn checked_output(program: &str, output: std::process::Output) -> Result<String> {
    if !output.status.success() {
        return Err(Error::new(
            ErrorCode::NetworkFailure,
            format!("Native network tool {program} failed: {}", output.status),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| failure("Native network command returned invalid text"))
}
fn run(program: &str, args: &[&str]) -> Result<String> {
    checked_output(
        program,
        command(
            program,
            &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            None,
            false,
        )?,
    )
}
fn change(program: &str, args: &[String], input: Option<&str>) -> Result<()> {
    checked_output(program, command(program, args, input, true)?).map(|_| ())
}
fn mutation(kind: &str, name: String, intended: Option<Value>) -> Result<Mutation> {
    let kind = if matches!(
        kind,
        "linux-mtu"
            | "linux-up"
            | "linux-address"
            | "linux-addrgen"
            | "linux-dns"
            | "linux-domains"
            | "linux-default-dns"
            | "mac-mtu"
            | "mac-up"
            | "mac-address"
            | "mac-auto-route"
    ) {
        let interface = name
            .split('|')
            .next()
            .ok_or_else(|| failure("Missing journal interface"))?;
        format!("{kind}@{}", crate::interface::resolve(interface)?.index)
    } else {
        kind.to_owned()
    };
    let key = Key { kind, name };
    let before = read(&key)?;
    Ok(Mutation {
        key,
        before,
        intended,
        applied: None,
    })
}
pub(crate) fn plan(
    config: &NetworkConfig,
    _transaction: crate::TransactionId,
) -> Result<Vec<Mutation>> {
    config.validate()?;
    if matches!(config.transport_peer, std::net::IpAddr::V6(address) if address.is_unicast_link_local())
    {
        return Err(failure(
            "Link-local IPv6 transport peers require an explicit native scope",
        ));
    }
    safe_name(&config.interface.name)?;
    if crate::interface::resolve(&config.interface.name)? != config.interface {
        return Err(failure("Tunnel interface identity changed"));
    }
    trusted_script()?;
    let mut mutations: Vec<Mutation> = Vec::new();
    for item in native::plan(config)? {
        if let Some(previous) = mutations
            .iter()
            .find(|m| m.key.kind == item.key.kind && m.key.name == item.key.name)
        {
            if previous.before != item.before || previous.intended != item.intended {
                return Err(failure("Conflicting negotiated network mutations"));
            }
        } else {
            mutations.push(item);
        }
    }
    Ok(mutations)
}
fn native_key(key: &Key) -> Result<(Key, bool)> {
    let Some((kind, index)) = key.kind.split_once('@') else {
        return Ok((
            Key {
                kind: key.kind.clone(),
                name: key.name.clone(),
            },
            false,
        ));
    };
    if !matches!(
        kind,
        "linux-mtu"
            | "linux-up"
            | "linux-address"
            | "linux-addrgen"
            | "linux-dns"
            | "linux-domains"
            | "linux-default-dns"
            | "mac-mtu"
            | "mac-up"
            | "mac-address"
            | "mac-auto-route"
    ) {
        return Err(failure("Invalid interface-bound journal kind"));
    }
    let index: u32 = index
        .parse()
        .map_err(|_| failure("Invalid journal interface index"))?;
    let name = key
        .name
        .split('|')
        .next()
        .ok_or_else(|| failure("Missing journal interface"))?;
    safe_name(name)?;
    let name = std::ffi::CString::new(name).map_err(|_| failure("Invalid interface name"))?;
    let current = unsafe { libc::if_nametoindex(name.as_ptr()) };
    Ok((
        Key {
            kind: kind.to_owned(),
            name: key.name.clone(),
        },
        current == 0 || current != index,
    ))
}
pub(crate) fn vanished(key: &Key) -> Result<bool> {
    let (key, missing) = native_key(key)?;
    // Resolved's link object ceases to exist with the interface. Persistent
    // resolvconf records and Darwin dynamic-store fields are never skipped.
    Ok(missing && key.kind != "linux-resolvconf" && key.kind != "mac-store")
}
pub(crate) fn equivalent(key: &Key, actual: Option<&Value>, expected: Option<&Value>) -> bool {
    #[cfg(target_os = "macos")]
    if key.kind.starts_with("mac-auto-route@") {
        return native::automatic_equivalent(actual, expected);
    }
    let _ = key;
    actual == expected
}
pub(crate) fn read(key: &Key) -> Result<Option<Value>> {
    let (key, missing) = native_key(key)?;
    if missing {
        Ok(None)
    } else {
        native::read(&key)
    }
}
pub(crate) fn write(key: &Key, value: Option<&Value>) -> Result<()> {
    let (key, missing) = native_key(key)?;
    if missing {
        return Err(failure("Journaled interface no longer exists"));
    }
    native::write(&key, value)
}
pub(crate) fn apply_script(
    config: &NetworkConfig,
    reason: NetworkReason,
    mutations: &[Mutation],
    operation: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    config.validate()?;
    if reason != NetworkReason::Disconnect
        && crate::interface::resolve(&config.interface.name)? != config.interface
    {
        return Err(failure("Tunnel interface identity changed"));
    }
    lifecycle::execute(config, reason, mutations, operation)
}

pub(crate) fn apply_one(config: &NetworkConfig, item: &Mutation) -> Result<Option<Value>> {
    let current = read(&item.key)?;
    if current != item.before
        && !equivalent(&item.key, current.as_ref(), item.intended.as_ref())
        && !native::implicit_address_route(
            config,
            &item.key,
            current.as_ref(),
            item.before.as_ref(),
        )
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Network state changed during transaction application",
        ));
    }
    if !equivalent(&item.key, current.as_ref(), item.intended.as_ref()) {
        write(&item.key, item.intended.as_ref())?;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let actual = read(&item.key)?;
        if equivalent(&item.key, actual.as_ref(), item.intended.as_ref()) {
            return Ok(actual);
        }
        let pending_address = item.key.kind.contains("-address@")
            && actual
                .as_ref()
                .is_some_and(|v| v.get("unusable") == Some(&Value::Bool(true)));
        if !pending_address || Instant::now() >= deadline {
            return Err(failure(
                "Native network mutation did not produce the journaled state",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}
pub(crate) fn observe(config: &NetworkConfig) -> Result<NetworkObservation> {
    config.validate()?;
    if crate::interface::resolve(&config.interface.name)? != config.interface {
        return Err(failure("Tunnel interface identity changed"));
    }
    native::observe(config)
}
