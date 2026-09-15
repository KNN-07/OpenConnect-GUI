//! Safe entrypoint to the process-lifetime native ABI and single-owner session workers.
//! No native session pointer or allocation crosses the worker boundary.
pub mod auth;
pub mod browser;
mod loading;
#[cfg(windows)]
pub mod process_tree;
pub mod tunnel;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    unsafe_op_in_unsafe_fn
)]
pub(crate) mod abi {
    include!(concat!(env!("OUT_DIR"), "/openconnect.rs"));
}

use ocvpn_model::{Capabilities, Error, ErrorCode, ProtocolInfo, Result};
use std::{
    ffi::c_char,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const REQUIRED: [(&str, &str); 7] = [
    ("anyconnect", "Cisco AnyConnect / ocserv"),
    ("nc", "Juniper Network Connect"),
    ("pulse", "Ivanti / Pulse Connect Secure"),
    ("gp", "Palo Alto GlobalProtect"),
    ("f5", "F5 BIG-IP"),
    ("fortinet", "Fortinet FortiGate"),
    ("array", "Array Networks"),
];

// A process can initialize exactly one native runtime, including development mode.
// Failure after loading is cached too: retrying SSL initialization is not safe.
static LOADED: Mutex<Option<LoadedRuntime>> = Mutex::new(None);

struct LoadedRuntime {
    root: PathBuf,
    _native: Arc<abi::OpenConnect>,
    result: Result<Engine>,
}

#[derive(Clone)]
pub struct Engine {
    capabilities: Capabilities,
    native: Arc<abi::OpenConnect>,
}

/// Fixed installation layout; never selected by environment or a profile.
pub fn installed_native_directory() -> Result<PathBuf> {
    loading::installed_root()
}

/// Verify a fixed installed executable/helper with the same ownership and ACL
/// policy used for the native dependency closure. Does not accept symlink files.
pub fn validate_installed_file(path: &Path) -> Result<()> {
    loading::validate_installed_file(path)
}

impl Engine {
    /// Load only the protected, fixed installed native runtime. No environment or
    /// frontend-controlled path participates in selecting the library.
    pub fn load() -> Result<Self> {
        Self::load_at(&loading::installed_root()?, true)
    }

    pub fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.capabilities.clone())
    }

    /// Load an explicitly chosen local build for native verification only.
    ///
    /// # Safety
    /// The caller must trust every binary and dependency in this directory. Loading
    /// a library executes arbitrary native code. Never pass a frontend/user profile
    /// value here, and never enable this feature in a production interface build.
    /// A process cannot switch between installed and development native runtimes.
    #[cfg(feature = "development")]
    pub unsafe fn load_for_development(root: &Path) -> Result<Self> {
        Self::load_at(root, false)
    }

    fn load_at(root: &Path, production: bool) -> Result<Self> {
        let root = loading::validate_root(root, production)?;
        let mut loaded = LOADED.lock().map_err(|_| {
            unavailable("Native initialization lock failed; restart the application")
        })?;
        if let Some(previous) = loaded.as_ref() {
            if previous.root != root {
                return Err(unavailable(
                    "A different native runtime is already loaded; restart before changing runtimes",
                ));
            }
            return previous.result.clone();
        }
        let manifest = loading::verify_manifest(&root, production)?;
        // SAFETY: production validates protected installation ownership and the
        // manifest; the development caller explicitly assumes this responsibility.
        let library =
            unsafe { loading::open_library(&root.join(loading::library_relative_path()))? };
        let native = unsafe { abi::OpenConnect::from_library(library) }
            .map_err(|_| unavailable("Bundled OpenConnect is missing a required API 5.9 or bridge ABI 4 symbol; repair the matching native package"))?;
        // SSL can retain callbacks/global data even when initialization fails. Do
        // not unload the DLL after this point, including discovery failure paths.
        let native = Arc::new(native);
        let result = discover(&native, &manifest).map(|capabilities| Self {
            capabilities,
            native: native.clone(),
        });
        *loaded = Some(LoadedRuntime {
            root,
            _native: native,
            result: result.clone(),
        });
        result
    }
}

fn unavailable(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::EngineUnavailable, message)
}

fn discover(native: &abi::OpenConnect, manifest: &loading::Manifest) -> Result<Capabilities> {
    // SAFETY: generated signatures come from pinned headers; all symbols were
    // required at load time and the library is retained for the process lifetime.
    let (api_major, api_minor, bridge, hpke) = unsafe {
        (
            native.ocgui_api_version_major(),
            native.ocgui_api_version_minor(),
            native.ocgui_bridge_abi(),
            native.ocgui_has_hpke(),
        )
    };
    if api_major != 5 || api_minor < 9 || [api_major, api_minor] != manifest.api || bridge != 4 {
        return Err(unavailable(
            "Loaded native ABI disagrees with its manifest or is incompatible; API 5.9+ within major 5 and bridge ABI 4 are required",
        ));
    }
    if hpke != 1 {
        return Err(unavailable(
            "Loaded OpenConnect lacks required HPKE support; rebuild with GnuTLS HKDF, hogweed/nettle and GMP",
        ));
    }
    let ssl_status = unsafe { native.openconnect_init_ssl() };
    if ssl_status != 0 {
        return Err(unavailable(format!(
            "OpenConnect SSL initialization failed (native code {ssl_status}); verify the bundled GnuTLS runtime and restart"
        )));
    }
    let version = unsafe { native_text(native.openconnect_get_version(), 256, "version")? };
    if version != manifest.runtime_version {
        return Err(unavailable(
            "Loaded OpenConnect version differs from the pinned 9.21 native manifest; repair the installation",
        ));
    }
    let mut raw = std::ptr::null_mut();
    let count = unsafe { native.openconnect_get_supported_protocols(&mut raw) };
    // The matching native free function runs on every return path, even when a
    // malformed enumeration or incomplete release protocol set is diagnosed.
    let allocation = ProtocolAllocation { native, raw };
    if !(1..=256).contains(&count) || allocation.raw.is_null() {
        return Err(unavailable(format!(
            "OpenConnect protocol enumeration failed or exceeded its bound (native result {count})"
        )));
    }
    let entries = unsafe { std::slice::from_raw_parts(allocation.raw, count as usize) };
    let mut protocols = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = unsafe { native_text(entry.name, 128, "protocol identifier")? };
        if id.is_empty()
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            || protocols.iter().any(|p: &ProtocolInfo| p.id == id)
        {
            return Err(unavailable(
                "OpenConnect returned an invalid or duplicate protocol identifier",
            ));
        }
        let native_label = unsafe { native_text(entry.pretty_name, 1024, "protocol label")? };
        let label = REQUIRED
            .iter()
            .find(|(name, _)| *name == id)
            .map_or(native_label, |(_, label)| (*label).to_owned());
        let description = unsafe { native_text(entry.description, 4096, "protocol description")? };
        protocols.push(ProtocolInfo {
            id,
            label,
            description,
            flags: entry.flags,
        });
    }
    let missing: Vec<_> = REQUIRED
        .iter()
        .filter(|(id, _)| !protocols.iter().any(|p| p.id == *id))
        .map(|(id, _)| *id)
        .collect();
    if !missing.is_empty() {
        return Err(unavailable(format!(
            "Bundled OpenConnect is missing required protocols: {}; install the complete native runtime",
            missing.join(", ")
        )));
    }
    let (pkcs11, oath, stoken, yubioath) = unsafe {
        (
            native.openconnect_has_pkcs11_support(),
            native.openconnect_has_oath_support(),
            native.openconnect_has_stoken_support(),
            native.openconnect_has_yubioath_support(),
        )
    };
    Ok(Capabilities {
        engine_version: version,
        api_major,
        api_minor,
        protocols,
        pkcs11: pkcs11 > 0,
        totp: oath > 0,
        hotp: oath >= 2,
        stoken: stoken > 0,
        yubioath: yubioath > 0,
        hpke: true,
    })
}

struct ProtocolAllocation<'a> {
    native: &'a abi::OpenConnect,
    raw: *mut abi::oc_vpn_proto,
}
impl Drop for ProtocolAllocation<'_> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // Native allocator and native deallocator always stay in the same DLL.
            unsafe { self.native.openconnect_free_supported_protocols(self.raw) };
        }
    }
}

/// Caller guarantees a valid NUL-terminated native string. The bound constrains
/// copied metadata; an ABI-breaking malicious library is already executable code.
unsafe fn native_text(pointer: *const c_char, limit: usize, field: &str) -> Result<String> {
    if pointer.is_null() {
        return Err(unavailable(format!("OpenConnect returned a null {field}")));
    }
    for length in 0..limit {
        if unsafe { *pointer.add(length) } == 0 {
            let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) };
            let text = std::str::from_utf8(bytes)
                .map_err(|_| unavailable(format!("OpenConnect returned a non-UTF-8 {field}")))?;
            return Ok(text
                .chars()
                .filter(|character| !character.is_control())
                .collect());
        }
    }
    Err(unavailable(format!(
        "OpenConnect {field} exceeds the metadata size limit"
    )))
}
