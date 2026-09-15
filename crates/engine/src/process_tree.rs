//! Windows descendant lifetime bound to an owned kernel JobObject handle.
use ocvpn_model::{Error, ErrorCode, Result};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
fn failure() -> Error {
    Error::new(
        ErrorCode::RuntimeFailure,
        "Cannot establish or terminate owned process tree",
    )
}
pub struct ProcessTree {
    handle: OwnedHandle,
}
impl ProcessTree {
    /// Assign before releasing a private startup handshake. The caller must keep
    /// the child gated until assignment succeeds; no descendant can escape then.
    pub fn attach(process: BorrowedHandle<'_>) -> Result<Self> {
        unsafe {
            let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if raw.is_null() {
                return Err(failure());
            }
            let handle = OwnedHandle::from_raw_handle(raw);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            ) == 0
            {
                return Err(failure());
            }
            if AssignProcessToJobObject(handle.as_raw_handle(), process.as_raw_handle()) == 0 {
                return Err(failure());
            }
            Ok(Self { handle })
        }
    }
    pub fn terminate(&self) -> Result<()> {
        if unsafe { TerminateJobObject(self.handle.as_raw_handle(), 1) } == 0 {
            Err(failure())
        } else {
            Ok(())
        }
    }
    /// Zero means every assigned process and inherited descendant has exited.
    /// Keep the job handle until this succeeds before recovering shared state.
    pub fn active_processes(&self) -> Result<u32> {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(failure());
        }
        Ok(accounting.ActiveProcesses)
    }
}
