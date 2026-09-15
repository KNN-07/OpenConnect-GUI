use super::*;
use std::{
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};
fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}
struct Local(*mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(crate) fn privileged() -> Result<()> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(denied());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut size = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    } == 0
        || elevation.TokenIsElevated == 0
    {
        return Err(denied());
    }
    Ok(())
}
fn trusted_sid(sid: PSID) -> bool {
    !sid.is_null()
        && unsafe { IsValidSid(sid) } != 0
        && (unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0
            || unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0)
}
fn inspect(handle: HANDLE, private: bool) -> Result<()> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    if unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    } != 0
    {
        return Err(denied());
    }
    let _descriptor = Local(descriptor);
    if !trusted_sid(owner) || acl.is_null() {
        return Err(denied());
    }
    for i in 0..unsafe { (*acl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, u32::from(i), &mut ace) } == 0 {
            return Err(denied());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE {
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
            // Ancestors may allow creating unrelated children (ProgramData);
            // deleting/replacing an existing protected child must remain denied.
            let forbidden = if private {
                u32::MAX
            } else {
                FILE_DELETE_CHILD
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | DELETE
                    | WRITE_DAC
                    | WRITE_OWNER
                    | GENERIC_WRITE
                    | GENERIC_ALL
            };
            if allowed.Mask & forbidden != 0 && !trusted_sid(sid) {
                return Err(denied());
            }
        } else if u32::from(header.AceType) != ACCESS_DENIED_ACE_TYPE {
            return Err(denied());
        }
    }
    Ok(())
}
fn handle(
    path: &Path,
    access: u32,
    creation: u32,
    attrs: *const SECURITY_ATTRIBUTES,
) -> Result<OwnedHandle> {
    let p = wide(path);
    let raw = unsafe {
        CreateFileW(
            p.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            attrs,
            creation,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(denied());
    }
    let h = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(h.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    Ok(h)
}
pub(crate) fn check(path: &Path, private: bool) -> Result<()> {
    let h = handle(path, READ_CONTROL, OPEN_EXISTING, ptr::null())?;
    inspect(h.as_raw_handle(), private)
}
fn descriptor() -> Result<Local> {
    let s: Vec<u16> = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut p = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), 1, &mut p, ptr::null_mut())
    } == 0
    {
        return Err(denied());
    }
    Ok(Local(p))
}
pub(crate) fn directory(path: &Path) -> Result<()> {
    privileged()?;
    if path.exists() {
        return check(path, true);
    }
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            directory(parent)?;
        } else {
            check(parent, false)?;
        }
    }
    let d = descriptor()?;
    let a = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: d.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &a) } == 0 && !path.exists() {
        return Err(denied());
    }
    check(path, true)
}
pub(crate) fn open(path: &Path, create: bool) -> Result<File> {
    let d = descriptor()?;
    let a = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: d.0,
        bInheritHandle: 0,
    };
    let h = handle(
        path,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        if create { OPEN_ALWAYS } else { OPEN_EXISTING },
        &a,
    )?;
    inspect(h.as_raw_handle(), true)?;
    Ok(File::from(h))
}
pub(crate) fn sync_directory(_path: &Path) -> Result<()> {
    // Windows commits each replacement with MOVEFILE_WRITE_THROUGH after FlushFileBuffers.
    Ok(())
}
