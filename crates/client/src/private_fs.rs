//! Private unprivileged files. Existing unsafe files are rejected, not followed or repaired.
use ocvpn_model::{Error, ErrorCode, Result};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

fn error(path: &Path, message: &str) -> Error {
    let mut error = Error::new(ErrorCode::RuntimeFailure, message);
    error.details = Some(path.display().to_string());
    error
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| error(path, "Cannot locate working directory"))?
            .join(path)
    };
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(error(
            &path,
            "Parent traversal is not permitted in metadata paths",
        ));
    }
    Ok(path)
}
fn check_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || platform::reparse(&metadata) {
                    return Err(error(
                        ancestor,
                        "Symlinks and reparse points are not permitted",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error(ancestor, "Cannot inspect metadata path")),
        }
    }
    Ok(())
}
pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    let path = absolute(path)?;
    check_ancestors(&path)?;
    if !path.exists() {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                ensure_private_directory(parent)?;
            }
        }
        platform::create_directory(&path)?;
    }
    platform::verify_directory(&path)
}
pub(crate) fn open_private_lock(path: &Path) -> Result<File> {
    let path = absolute(path)?;
    check_ancestors(&path)?;
    platform::open(&path, true, false)?.ok_or_else(|| error(&path, "Cannot create private lock"))
}
pub(crate) fn open_private_read(path: &Path) -> Result<Option<File>> {
    let path = absolute(path)?;
    check_ancestors(&path)?;
    platform::open(&path, false, false)
}
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    let path = absolute(path)?;
    check_ancestors(&path)?;
    let parent = path
        .parent()
        .ok_or_else(|| error(&path, "Missing parent directory"))?;
    // Exports may target a normal user directory. Only the output itself must be private.
    if !parent.is_dir() {
        return Err(error(parent, "Destination directory does not exist"));
    }
    if let Some(_existing) = platform::open(&path, false, false)? {
        if !overwrite {
            return Err(Error::new(
                ErrorCode::Conflict,
                "Destination already exists",
            ));
        }
    }
    let temporary = parent.join(format!(".ocvpn-{}.tmp", Uuid::new_v4()));
    let mut created = false;
    let result = (|| {
        let mut file = platform::open(&temporary, true, true)?
            .ok_or_else(|| error(&temporary, "Cannot create temporary file"))?;
        created = true;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| error(&temporary, "Cannot durably write metadata"))?;
        drop(file);
        platform::replace(&temporary, &path, overwrite)?;
        #[cfg(unix)]
        platform::sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        fs::{DirBuilder, OpenOptions},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    pub fn reparse(_: &fs::Metadata) -> bool {
        false
    }
    fn verify(path: &Path, metadata: &fs::Metadata, directory: bool) -> Result<()> {
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || (directory && !metadata.is_dir())
            || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err(error(
                path,
                "Metadata must be owned exclusively by this user with private permissions",
            ));
        }
        Ok(())
    }
    pub fn create_directory(path: &Path) -> Result<()> {
        match DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(_) => Err(error(path, "Cannot create private directory")),
        }
    }
    pub fn verify_directory(path: &Path) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| error(path, "Cannot open private directory"))?;
        verify(
            path,
            &file
                .metadata()
                .map_err(|_| error(path, "Cannot inspect private directory"))?,
            true,
        )
    }
    pub fn open(path: &Path, create: bool, exclusive: bool) -> Result<Option<File>> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        if exclusive {
            options.create_new(true);
        } else {
            options.create(create);
        }
        let file = match options.open(path) {
            Ok(file) => file,
            Err(e) if !create && e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(error(path, "Cannot open private metadata file")),
        };
        verify(
            path,
            &file
                .metadata()
                .map_err(|_| error(path, "Cannot inspect private metadata file"))?,
            false,
        )?;
        Ok(Some(file))
    }
    pub fn replace(source: &Path, destination: &Path, overwrite: bool) -> Result<()> {
        if overwrite {
            fs::rename(source, destination)
                .map_err(|_| error(destination, "Cannot atomically replace metadata"))
        } else {
            fs::hard_link(source, destination).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::new(ErrorCode::Conflict, "Destination already exists")
                } else {
                    error(destination, "Cannot atomically publish metadata")
                }
            })?;
            fs::remove_file(source)
                .map_err(|_| error(source, "Cannot remove temporary metadata link"))
        }
    }
    pub fn sync_directory(path: &Path) -> Result<()> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| error(path, "Cannot durably sync metadata directory"))
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            fs::MetadataExt,
            io::{AsRawHandle, FromRawHandle},
        },
        ptr,
    };
    type Handle = *mut c_void;
    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }
    #[repr(C)]
    struct Acl {
        revision: u8,
        reserved: u8,
        size: u16,
        count: u16,
        reserved2: u16,
    }
    #[repr(C)]
    struct Ace {
        kind: u8,
        flags: u8,
        size: u16,
        mask: u32,
        sid: u32,
    }
    #[repr(C)]
    struct FileInformation {
        attributes: u32,
        created: [u32; 2],
        accessed: [u32; 2],
        written: [u32; 2],
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            attributes: *const SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn ReplaceFileW(
            destination: *const u16,
            source: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *mut c_void,
            reserved: *mut c_void,
        ) -> i32;
        fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
        fn GetFileInformationByHandle(handle: Handle, information: *mut FileInformation) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            length: u32,
            needed: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: Handle,
            kind: u32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut Acl,
            sacl: *mut *mut Acl,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
        fn EqualSid(a: *const c_void, b: *const c_void) -> i32;
    }
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    struct Token(Handle);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Identity {
        token_data: Vec<usize>,
        descriptor: Local,
    }
    impl Identity {
        fn sid(&self) -> *const c_void {
            unsafe { *(self.token_data.as_ptr() as *const *const c_void) }
        }
        fn new(path: &Path) -> Result<Self> {
            unsafe {
                let mut token = ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), 8, &mut token) == 0 {
                    return Err(error(path, "Cannot inspect user identity"));
                }
                let token = Token(token);
                let mut needed = 0;
                GetTokenInformation(token.0, 1, ptr::null_mut(), 0, &mut needed);
                if needed == 0 {
                    return Err(error(path, "Cannot inspect user SID"));
                }
                let mut token_data =
                    vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
                if GetTokenInformation(
                    token.0,
                    1,
                    token_data.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                ) == 0
                {
                    return Err(error(path, "Cannot read user SID"));
                }
                let sid = *(token_data.as_ptr() as *const *const c_void);
                let mut text = ptr::null_mut();
                if ConvertSidToStringSidW(sid, &mut text) == 0 {
                    return Err(error(path, "Cannot encode user SID"));
                }
                let text_owner = Local(text.cast());
                let mut length = 0;
                while *text.add(length) != 0 {
                    length += 1;
                }
                let sid_string = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
                drop(text_owner);
                let sddl: Vec<u16> = format!("O:{sid_string}D:P(A;OICI;FA;;;{sid_string})")
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                let mut descriptor = ptr::null_mut();
                if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                ) == 0
                {
                    return Err(error(path, "Cannot build private user ACL"));
                }
                Ok(Self {
                    token_data,
                    descriptor: Local(descriptor),
                })
            }
        }
        fn attributes(&self) -> SecurityAttributes {
            SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor: self.descriptor.0,
                inherit: 0,
            }
        }
        fn verify(&self, file: &File, path: &Path) -> Result<()> {
            unsafe {
                let mut owner = ptr::null_mut();
                let mut acl = ptr::null_mut();
                let mut descriptor = ptr::null_mut();
                if GetSecurityInfo(
                    file.as_raw_handle(),
                    1,
                    1 | 4,
                    &mut owner,
                    ptr::null_mut(),
                    &mut acl,
                    ptr::null_mut(),
                    &mut descriptor,
                ) != 0
                {
                    return Err(error(path, "Cannot inspect metadata ACL"));
                }
                let _descriptor = Local(descriptor);
                if owner.is_null()
                    || EqualSid(owner, self.sid()) == 0
                    || acl.is_null()
                    || (*acl).count != 1
                {
                    return Err(error(path, "Metadata must have a user-only ACL"));
                }
                let mut ace = ptr::null_mut();
                if GetAce(acl, 0, &mut ace) == 0 {
                    return Err(error(path, "Cannot inspect metadata ACE"));
                }
                let ace = &*(ace as *const Ace);
                if ace.kind != 0
                    || ace.flags & 8 != 0
                    || ace.mask != 0x1f01ff
                    || EqualSid((&ace.sid as *const u32).cast(), self.sid()) == 0
                {
                    return Err(error(path, "Metadata must grant access only to its user"));
                }
                Ok(())
            }
        }
    }
    fn wide(path: &Path) -> Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(error(path, "Invalid path"));
        }
        value.push(0);
        Ok(value)
    }
    pub fn reparse(metadata: &fs::Metadata) -> bool {
        metadata.file_attributes() & 0x400 != 0
    }
    pub fn create_directory(path: &Path) -> Result<()> {
        let identity = Identity::new(path)?;
        let name = wide(path)?;
        if unsafe { CreateDirectoryW(name.as_ptr(), &identity.attributes()) } == 0
            && std::io::Error::last_os_error().raw_os_error() != Some(183)
        {
            return Err(error(path, "Cannot create private directory"));
        }
        Ok(())
    }
    fn handle(path: &Path, create: bool, exclusive: bool, directory: bool) -> Result<Option<File>> {
        let identity = Identity::new(path)?;
        let name = wide(path)?;
        let access = if create {
            0x80000000 | 0x40000000 | 0x20000
        } else {
            0x80000000 | 0x20000
        };
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                1 | 2 | 4,
                &identity.attributes(),
                if exclusive {
                    1
                } else if create {
                    4
                } else {
                    3
                },
                0x00200000 | if directory { 0x02000000 } else { 0x80 },
                ptr::null_mut(),
            )
        };
        if raw as isize == -1 {
            let code = std::io::Error::last_os_error().raw_os_error();
            if !create && matches!(code, Some(2) | Some(3)) {
                return Ok(None);
            }
            return Err(error(path, "Cannot open private metadata"));
        }
        let file = unsafe { File::from_raw_handle(raw) };
        let metadata = file
            .metadata()
            .map_err(|_| error(path, "Cannot inspect metadata handle"))?;
        if reparse(&metadata)
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err(error(path, "Unsafe metadata file type"));
        }
        let mut information: FileInformation = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0
            || (!directory && information.links != 1)
        {
            return Err(error(path, "Metadata hard links are not permitted"));
        }
        identity.verify(&file, path)?;
        Ok(Some(file))
    }
    pub fn verify_directory(path: &Path) -> Result<()> {
        handle(path, false, false, true)?
            .ok_or_else(|| error(path, "Private directory missing"))?;
        Ok(())
    }
    pub fn open(path: &Path, create: bool, exclusive: bool) -> Result<Option<File>> {
        handle(path, create, exclusive, false)
    }
    pub fn replace(source: &Path, destination: &Path, overwrite: bool) -> Result<()> {
        let source = wide(source)?;
        let destination_name = wide(destination)?;
        if overwrite
            && unsafe {
                ReplaceFileW(
                    destination_name.as_ptr(),
                    source.as_ptr(),
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } != 0
        {
            return Ok(());
        }
        // Move without REPLACE_EXISTING closes the destination-creation race. ReplaceFile's
        // errors other than a missing destination must not be hidden by a fallback.
        if overwrite && std::io::Error::last_os_error().raw_os_error() != Some(2) {
            return Err(error(destination, "Cannot atomically replace metadata"));
        }
        if unsafe { MoveFileExW(source.as_ptr(), destination_name.as_ptr(), 8) } == 0 {
            if matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(80) | Some(183)
            ) {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "Destination already exists",
                ));
            }
            return Err(error(destination, "Cannot atomically publish metadata"));
        }
        Ok(())
    }
}
