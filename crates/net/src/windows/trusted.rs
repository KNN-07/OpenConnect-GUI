use super::{check, fail, wide_string};
use ocvpn_model::{Error, ErrorCode, Result};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Com::CoTaskMemFree, SystemInformation::GetSystemDirectoryW},
    UI::Shell::{FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};
fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf> {
    let mut folder = ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut folder) } < 0 {
        return Err(denied());
    }
    let text = unsafe { wide_string(folder) };
    unsafe { CoTaskMemFree(folder.cast()) };
    let path = PathBuf::from(text?);
    if !path.is_absolute() {
        return Err(denied());
    }
    Ok(path)
}
pub(super) fn journal_root() -> Result<PathBuf> {
    Ok(known_folder(&FOLDERID_ProgramData)?.join(r"OpenConnectGUI\network"))
}
fn installed_paths() -> Result<(PathBuf, PathBuf)> {
    let script = known_folder(&FOLDERID_ProgramFiles)?.join(r"OpenConnect GUI\resources\nrpt.ps1");
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(denied());
    }
    let system = PathBuf::from(String::from_utf16(&buffer[..length]).map_err(|_| denied())?);
    if !script.is_absolute() || !system.is_absolute() {
        return Err(denied());
    }
    Ok((script, system))
}
fn denied() -> Error {
    Error::new(
        ErrorCode::AuthorizationDenied,
        "Network changes require an elevated administrator and protected installed assets",
    )
}
pub(super) fn privileged() -> Result<()> {
    let mut sid = [0u64; 9];
    let mut bytes = 72;
    let mut member = 0;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut bytes,
        )
    } == 0
        || unsafe {
            CheckTokenMembership(ptr::null_mut(), sid.as_ptr().cast_mut().cast(), &mut member)
        } == 0
        || member == 0
    {
        return Err(denied());
    }
    Ok(())
}
unsafe fn trusted_sid(sid: PSID) -> Result<bool> {
    if sid.is_null() {
        return Ok(false);
    }
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(denied());
    }
    let result = unsafe { wide_string(text) };
    unsafe { LocalFree(text.cast()) };
    Ok(matches!(
        result?.as_str(),
        "S-1-5-18"
            | "S-1-5-32-544"
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    ))
}
fn protected(path: &Path) -> Result<Vec<File>> {
    let mut held = Vec::new();
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if !current.has_root() {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .access_mode(0x00020080)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)
            .map_err(|_| denied())?;
        let metadata = file.metadata().map_err(|_| denied())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(denied());
        }
        let mut owner = ptr::null_mut();
        let mut acl = ptr::null_mut();
        let mut sd = ptr::null_mut();
        check(unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut sd,
            )
        })?;
        let result = (|| -> Result<()> {
            if !unsafe { trusted_sid(owner) }? || acl.is_null() {
                return Err(denied());
            }
            for index in 0..unsafe { (*acl).AceCount } {
                let mut ace = ptr::null_mut();
                if unsafe { GetAce(acl, index.into(), &mut ace) } == 0 {
                    return Err(denied());
                }
                let header = unsafe { &*ace.cast::<ACE_HEADER>() };
                if header.AceFlags & 8 != 0 {
                    continue;
                } // INHERIT_ONLY_ACE does not grant access here.
                if header.AceType == 1 {
                    continue;
                } // Deny ACEs cannot widen access.
                if header.AceType != 0 {
                    return Err(denied());
                }
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                // Creation of unrelated children is harmless: existing components stay locked.
                let write_mask = if metadata.is_dir() {
                    0x500D0150
                } else {
                    0x500D0156
                };
                if allowed.Mask & write_mask != 0
                    && !unsafe { trusted_sid(ptr::addr_of!(allowed.SidStart).cast_mut().cast()) }?
                {
                    return Err(denied());
                }
            }
            Ok(())
        })();
        unsafe { LocalFree(sd) };
        result?;
        held.push(file);
    }
    Ok(held)
}
fn helper_not_quiet() -> Error {
    Error::new(
        ErrorCode::RecoveryRequired,
        "Cannot confirm Windows DNS helper termination; network journal retained for repair",
    )
}
fn wait_helper(tree: &ocvpn_engine::process_tree::ProcessTree) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if tree.active_processes().map_err(|_| helper_not_quiet())? == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(helper_not_quiet());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
pub(super) fn nrpt(request: &Value) -> Result<Value> {
    use std::os::windows::io::AsHandle;
    privileged()?;
    let (script, system) = installed_paths()?;
    let powershell = system.join(r"WindowsPowerShell\v1.0\powershell.exe");
    let _script = protected(&script)?;
    let _executable = protected(&powershell)?;
    let windows = system.parent().ok_or_else(denied)?;
    let input = serde_json::to_vec(request).map_err(|_| fail())?;
    if input.len() > 131072 {
        return Err(fail());
    }
    let mut child = Command::new(&powershell)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(&script)
        .current_dir(&system)
        .env_clear()
        .env("SystemRoot", windows)
        .env("WINDIR", windows)
        .env(
            "PSModulePath",
            system.join(r"WindowsPowerShell\v1.0\Modules"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| fail())?;
    // The fixed script cannot mutate until its private JSON input reaches EOF.
    // Assign the job before releasing that gate, including offline recovery.
    let tree = match ocvpn_engine::process_tree::ProcessTree::attach(child.as_handle()) {
        Ok(tree) => tree,
        Err(error) => {
            drop(child.stdin.take());
            let _ = child.kill();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return Err(error),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    _ => return Err(helper_not_quiet()),
                }
            }
        }
    };
    let mut stdin = child.stdin.take().ok_or_else(fail)?;
    let stdout = child.stdout.take().ok_or_else(fail)?;
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        stdout.take(262145).read_to_end(&mut out).map(|_| out)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < Duration::from_secs(20) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => break Err(fail()),
        }
    };
    if status.is_err() {
        tree.terminate().map_err(|_| helper_not_quiet())?;
    }
    wait_helper(&tree)?;
    if status.is_err() {
        let _ = child.wait();
    }
    writer.join().map_err(|_| fail())?.map_err(|_| fail())?;
    let output = reader.join().map_err(|_| fail())?.map_err(|_| fail())?;
    if !status?.success() || output.len() > 262144 {
        return Err(Error::new(
            ErrorCode::NetworkFailure,
            "The installed Windows DNS helper could not complete. Check DNS Client permissions and the normal PowerShell execution policy; the application does not bypass that policy.",
        ));
    }
    serde_json::from_slice(&output).map_err(|_| fail())
}
