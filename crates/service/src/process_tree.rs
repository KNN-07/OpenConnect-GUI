//! Scope escalation to the worker launched by this supervisor, never a PID from IPC.
use ocvpn_model::{Error, ErrorCode, Result};
fn failure() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "Cannot establish or terminate owned worker process tree",
    )
}
#[cfg(unix)]
pub(crate) struct OwnedTree {
    group: i32,
    lifetime: crate::lifetime::WorkerExit,
}
#[cfg(unix)]
impl OwnedTree {
    pub(crate) fn attach(
        child: &tokio::process::Child,
        lifetime: crate::lifetime::WorkerExit,
    ) -> Result<Self> {
        Ok(Self {
            group: child
                .id()
                .ok_or_else(failure)?
                .try_into()
                .map_err(|_| failure())?,
            lifetime,
        })
    }
    // Called before reaping the group leader, so the numeric PGID cannot be reused.
    pub(crate) fn terminate(&self) -> Result<()> {
        if unsafe { libc::kill(-self.group, libc::SIGKILL) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            Err(failure())
        } else {
            Ok(())
        }
    }
    pub(crate) async fn wait_quiet(&self) -> Result<()> {
        // A helper can outlive or leave its worker process group. Only release
        // of every inherited lock reference proves they cannot mutate anymore.
        self.lifetime.wait_quiet().await
    }
}
#[cfg(windows)]
pub(crate) struct OwnedTree(ocvpn_engine::process_tree::ProcessTree);
#[cfg(windows)]
impl OwnedTree {
    pub(crate) fn attach(child: &tokio::process::Child) -> Result<Self> {
        let raw = child.raw_handle().ok_or_else(failure)?;
        let process = unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(raw) };
        ocvpn_engine::process_tree::ProcessTree::attach(process).map(Self)
    }
    pub(crate) fn terminate(&self) -> Result<()> {
        self.0.terminate()
    }
    fn quiet(&self) -> Result<bool> {
        self.0.active_processes().map(|count| count == 0)
    }
}
#[cfg(windows)]
impl OwnedTree {
    pub(crate) async fn wait_quiet(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match self.quiet() {
                Ok(true) => return Ok(()),
                Err(_) => {
                    return Err(Error::new(
                        ErrorCode::RecoveryRequired,
                        "Cannot establish that owned helpers have exited; network journal retained",
                    ));
                }
                Ok(false) if tokio::time::Instant::now() >= deadline => {
                    return Err(Error::new(
                        ErrorCode::RecoveryRequired,
                        "Owned helper processes are not yet quiescent; network journal retained",
                    ));
                }
                Ok(false) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    }
}
