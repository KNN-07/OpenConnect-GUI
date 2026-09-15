use crate::unavailable;
use ocvpn_model::Result;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufReader, Read},
    path::{Component, Path, PathBuf},
};

#[derive(Deserialize)]
pub(crate) struct Manifest {
    pub schema_version: u32,
    pub target: String,
    pub openconnect: String,
    pub runtime_version: String,
    pub api: [u32; 2],
    pub bridge_abi: u32,
    pub hpke: bool,
    pub files: BTreeMap<String, String>,
}

pub(crate) fn installed_root() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/usr/lib/openconnect-gui"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(PathBuf::from(
            "/Applications/OpenConnect GUI.app/Contents/Resources/native",
        ))
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::{
            System::Com::CoTaskMemFree,
            UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
        };
        let mut raw = std::ptr::null_mut();
        // The system known folder is not an environment-variable search path.
        let result = unsafe {
            SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, std::ptr::null_mut(), &mut raw)
        };
        if result < 0 || raw.is_null() {
            return Err(unavailable(
                "Cannot locate the system Program Files folder; repair the installation",
            ));
        }
        let path = unsafe {
            let mut length = 0;
            while *raw.add(length) != 0 {
                length += 1;
            }
            let path = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(
                raw, length,
            )));
            CoTaskMemFree(raw.cast());
            path
        };
        Ok(path.join("OpenConnect GUI/native"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(unavailable(
            "This platform has no supported bundled OpenConnect runtime",
        ))
    }
}

pub(crate) fn library_relative_path() -> &'static str {
    if cfg!(target_os = "windows") {
        "lib/libopenconnect-5.dll"
    } else if cfg!(target_os = "macos") {
        "lib/libopenconnect.5.dylib"
    } else {
        "lib/libopenconnect.so.5"
    }
}

pub(crate) fn validate_root(root: &Path, production: bool) -> Result<PathBuf> {
    if !root.is_absolute() {
        return Err(unavailable("Native runtime location must be absolute"));
    }
    let canonical = root.canonicalize().map_err(|_| {
        unavailable(format!(
            "Bundled native runtime is missing at {}; install or repair OpenConnect GUI",
            root.display()
        ))
    })?;
    if production {
        // An installed runtime must not redirect loading through user-writable ancestors.
        #[cfg(unix)]
        if canonical != root {
            return Err(unavailable(
                "Installed native runtime root redirects through a symlink; repair the installation",
            ));
        }
        check_protected(&canonical)?;
    }
    Ok(canonical)
}

fn check_protected(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|_| unavailable("Cannot inspect native runtime ownership"))?;
            #[cfg(target_os = "macos")]
            let admin_applications = ancestor == Path::new("/Applications")
                && metadata.uid() == 0
                && metadata.gid() == 80
                && metadata.mode() & 0o7777 == 0o775;
            #[cfg(not(target_os = "macos"))]
            let admin_applications = false;
            if metadata.uid() != 0
                || (metadata.mode() & 0o022 != 0 && !admin_applications)
                || metadata.file_type().is_symlink()
            {
                return Err(unavailable(format!(
                    "Native runtime path {} must be root-owned and not writable by group or other users",
                    ancestor.display()
                )));
            }
        }
    }
    #[cfg(windows)]
    {
        windows_protected(path)?;
    }
    Ok(())
}

pub(crate) fn validate_installed_file(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(unavailable("Installed file path must be absolute"));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| unavailable("Cannot inspect installed file"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(unavailable(
            "Installed file must be a regular, non-symlink file",
        ));
    }
    check_protected(path)
}

fn contained_file(root: &Path, relative: &Path, production: bool) -> Result<PathBuf> {
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(unavailable(
            "Native manifest contains a non-relative file location; repair the installation",
        ));
    }
    let path = root.join(relative).canonicalize().map_err(|_| {
        unavailable(format!(
            "Bundled native file {} is missing; repair the installation",
            relative.display()
        ))
    })?;
    if !path.starts_with(root) || !path.is_file() {
        return Err(unavailable(
            "Bundled native file escapes the installation directory",
        ));
    }
    if production {
        check_protected(&path)?;
    }
    Ok(path)
}

pub(crate) fn verify_manifest(root: &Path, production: bool) -> Result<Manifest> {
    let path = contained_file(root, Path::new("native-manifest.json"), production)?;
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(1024 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|_| unavailable("Cannot read native build manifest; repair the installation"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(unavailable("Native build manifest exceeds the size limit"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|_| unavailable("Native build manifest is invalid; repair the installation"))?;
    if manifest.schema_version != 1
        || manifest.openconnect != "9.21"
        || manifest.runtime_version != "v9.21-unknown"
        || manifest.bridge_abi != 4
    {
        return Err(unavailable(
            "Native manifest does not describe the pinned OpenConnect 9.21 / bridge ABI 4 build; repair the installation",
        ));
    }
    if manifest.target != env!("OCVPN_ENGINE_TARGET") {
        return Err(unavailable(format!(
            "Native runtime architecture/target mismatch: this application requires {}",
            env!("OCVPN_ENGINE_TARGET")
        )));
    }
    if manifest.api[0] != 5 || manifest.api[1] < 9 || !manifest.hpke {
        return Err(unavailable(
            "Native build requires compatible API 5.9 or later and HPKE (GnuTLS HKDF, hogweed/nettle, GMP); rebuild or repair the runtime",
        ));
    }
    if !manifest.files.contains_key(library_relative_path()) || manifest.files.len() > 4096 {
        return Err(unavailable(
            "Native build manifest has no bundled library entry or exceeds the file limit",
        ));
    }
    for (relative, expected) in &manifest.files {
        let path = contained_file(root, Path::new(relative), production)?;
        let mut file = BufReader::new(
            File::open(path).map_err(|_| unavailable("Cannot read bundled native dependency"))?,
        );
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| unavailable("Cannot verify bundled native dependency"))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if format!("{:x}", digest.finalize()) != *expected {
            return Err(unavailable(format!(
                "Bundled native file {relative} failed its SHA-256 integrity check; repair the installation"
            )));
        }
    }
    Ok(manifest)
}

pub(crate) unsafe fn open_library(path: &Path) -> Result<libloading::Library> {
    #[cfg(windows)]
    let result = unsafe {
        // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32:
        // neither PATH, CWD nor application-directory fallback is permitted.
        libloading::os::windows::Library::load_with_flags(path, 0x00000100 | 0x00000800)
            .map(libloading::Library::from)
    };
    #[cfg(not(windows))]
    let result = unsafe { libloading::Library::new(path) };
    result.map_err(|_| unavailable(format!("Cannot load bundled OpenConnect at {}: wrong architecture, missing dependency, or invalid native binary; repair the matching {} runtime", path.display(), env!("OCVPN_ENGINE_TARGET"))))
}
#[cfg(windows)]
fn windows_protected(path: &Path) -> Result<()> {
    fn denied() -> ocvpn_model::Error {
        unavailable("Installed path is not protected by administrator ownership and ACLs")
    }
    use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            ACCESS_ALLOWED_ACE, ACL,
            Authorization::{ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, IsWellKnownSid,
            OWNER_SECURITY_INFORMATION, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
    };
    struct NativeSid(*mut std::ffi::c_void);
    impl Drop for NativeSid {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let trusted_installer: Vec<u16> =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
            .encode_utf16()
            .chain(Some(0))
            .collect();
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(trusted_installer.as_ptr(), &mut sid) } == 0 {
        return Err(denied());
    }
    let trusted_installer = NativeSid(sid);
    let trusted = |sid: *mut std::ffi::c_void| unsafe {
        !sid.is_null()
            && (IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                || EqualSid(sid, trusted_installer.0) != 0)
    };
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| denied())?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(denied());
        }
        let name: Vec<u16> = ancestor.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut owner = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        unsafe {
            if GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            ) != 0
            {
                return Err(denied());
            }
            let result = (|| {
                if dacl.is_null() || !trusted(owner) {
                    return Err(denied());
                }
                for index in 0..(*dacl).AceCount {
                    let mut ace = std::ptr::null_mut();
                    if GetAce(dacl, index.into(), &mut ace) == 0 {
                        return Err(denied());
                    }
                    let kind = *(ace as *const u8);
                    // Ordinary deny/audit ACEs cannot grant write access. Object
                    // and callback allow ACEs need semantics we deliberately reject.
                    if matches!(kind, 1 | 2 | 3 | 6 | 7 | 8 | 10 | 12 | 13 | 14 | 15 | 17) {
                        continue;
                    }
                    if kind != 0 {
                        return Err(denied());
                    }
                    let ace = &*(ace as *const ACCESS_ALLOWED_ACE);
                    let sid = (&ace.SidStart as *const u32).cast_mut().cast();
                    if trusted(sid) {
                        continue;
                    }
                    if ace.Header.AceFlags & 0x08 != 0 {
                        continue;
                    } // INHERIT_ONLY
                    // Creating a different directory entry in a system ancestor
                    // does not grant replacement of an existing protected child.
                    let forbidden = if metadata.is_dir() {
                        0x500d_0040
                    } else {
                        0x500d_0156
                    };
                    if ace.Mask & forbidden != 0 {
                        return Err(denied());
                    }
                }
                Ok(())
            })();
            LocalFree(descriptor);
            result?;
        }
    }
    Ok(())
}
