use ocvpn_model::network::InterfaceIdentity;
use ocvpn_model::{Error, Result};

/// Resolve an existing kernel interface; never manufacture an index from a name.
pub fn resolve(name: &str) -> Result<InterfaceIdentity> {
    if name.is_empty()
        || name.len() > 256
        || name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
    {
        return Err(Error::invalid("Invalid tunnel interface name"));
    }
    let index = resolve_index(name)?;
    if index == 0 {
        return Err(Error::invalid("Tunnel interface does not exist"));
    }
    Ok(InterfaceIdentity {
        name: name.to_owned(),
        index,
    })
}

#[cfg(unix)]
fn resolve_index(name: &str) -> Result<u32> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| Error::invalid("Invalid tunnel interface name"))?;
    // SAFETY: name is a live NUL-terminated string; this API only queries the kernel.
    Ok(unsafe { libc::if_nametoindex(name.as_ptr()) })
}

#[cfg(windows)]
fn resolve_index(name: &str) -> Result<u32> {
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex},
        Ndis::NET_LUID_LH,
    };
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: the native union is an integer representation; zero is a valid initial value.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let mut index = 0;
    // SAFETY: pointers reference live, correctly sized values and a terminated UTF-16 alias.
    if unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) } != 0
        || unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } != 0
    {
        return Err(Error::invalid("Cannot resolve tunnel interface alias"));
    }
    Ok(index)
}

#[cfg(not(any(unix, windows)))]
compile_error!("ocvpn-net requires a Unix or Windows native interface API");
