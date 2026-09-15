//! Kernel open-file-description locks, never stale PID files. Never unlink these
//! files or explicitly LOCK_UN: descendants may still own the same description.
use ocvpn_model::{Error, ErrorCode, Result};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    time::Duration,
};

fn failure() -> Error {
    Error::new(
        ErrorCode::RecoveryRequired,
        "Privileged mutator lifetime is not quiescent; journal recovery is blocked",
    )
}
fn open(name: &str) -> Result<File> {
    crate::unix::validate_control_directory().map_err(|_| failure())?;
    let path = std::path::Path::new(crate::CONTROL_ENDPOINT).with_file_name(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| failure())?;
    let metadata = file.metadata().map_err(|_| failure())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(failure());
    }
    // fd 3 is reserved for the journal-aware script; stdio also gets remapped.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if fd < 0 {
        return Err(failure());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn try_exclusive(file: &File) -> Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => Ok(false),
        _ => Err(failure()),
    }
}
async fn acquire(file: &File) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if try_exclusive(file)? {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(failure());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(crate) struct DaemonLease {
    _file: File,
}
impl DaemonLease {
    pub(crate) async fn acquire() -> Result<()> {
        let file = open("mutator-lifetime.lock")?;
        acquire(&file).await?;
        // Every daemon descendant inherits this, including blocking recovery
        // tools. Keep EX throughout; own recovery never reacquires this lock.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
            return Err(failure());
        }
        // Retain until process exit, even if a cancelled startup or shutdown
        // leaves a blocking recovery task running after run_with_ready returns.
        static LEASE: std::sync::OnceLock<DaemonLease> = std::sync::OnceLock::new();
        LEASE.set(Self { _file: file }).map_err(|_| failure())
    }
}

/// Failed recovery tools may retain descendants; a later call must acquire a
/// fresh description rather than unlock or reuse the inherited one.
pub(crate) fn recover<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let file = open("recovery-lifetime.lock")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if try_exclusive(&file)? {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(failure());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
        return Err(failure());
    }
    let result = operation();
    let probe = open("recovery-lifetime.lock")?;
    drop(file);
    if !try_exclusive(&probe)? {
        return Err(failure());
    }
    result
}

/// Installer recovery runs outside the daemon, after its native stop check.
/// It must still exclude prior descendants and protect its own subprocesses
/// from an immediate concurrent daemon start.
#[cfg(target_os = "linux")]
pub(crate) fn offline_recover_all() -> Result<Vec<Error>> {
    let file = open("mutator-lifetime.lock")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if try_exclusive(&file)? {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(failure());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
        return Err(failure());
    }
    recover(ocvpn_net::recover_all)
}

pub(crate) struct WorkerLease {
    holder: File,
    probe: File,
}
impl WorkerLease {
    pub(crate) fn prepare(command: &mut tokio::process::Command) -> Result<Self> {
        let holder = open("worker-lifetime.lock")?;
        let probe = open("worker-lifetime.lock")?;
        if !try_exclusive(&holder)? {
            return Err(failure());
        }
        let fd = holder.as_raw_fd();
        // Only the worker inherits this lock. The supervisor and its recovery
        // children retain only CLOEXEC descriptors. No secret FD is changed.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(Self { holder, probe })
    }
    pub(crate) fn spawned(self) -> WorkerExit {
        drop(self.holder);
        WorkerExit(self.probe)
    }
}
pub(crate) struct WorkerExit(File);
impl WorkerExit {
    pub(crate) async fn wait_quiet(&self) -> Result<()> {
        acquire(&self.0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
    };
    #[test]
    fn inherited_description_blocks_recovery_until_descendant_exit() {
        // User-owned throwaway file; no root paths, network operations or PIDs.
        let path = std::env::temp_dir().join(format!("ocvpn-lifetime-{}", uuid::Uuid::new_v4()));
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(try_exclusive(&holder).unwrap());
        use std::os::unix::process::CommandExt;
        let fd = holder.as_raw_fd();
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "printf 'ready\\n'; read answer"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
        // Closing the supervisor's copy models abrupt death: no LOCK_UN.
        drop(holder);
        assert!(!try_exclusive(&probe).unwrap());
        child.stdin.take().unwrap().write_all(b"exit\n").unwrap();
        assert!(child.wait().unwrap().success());
        assert!(try_exclusive(&probe).unwrap());
    }
}
