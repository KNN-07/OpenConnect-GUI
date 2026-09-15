//! Borrowed browser certificates and secret page data cross only the pinned C ABI.
use crate::{Engine, abi};
use ocvpn_model::{
    BrowserPage, BrowserTlsPolicy, Error, ErrorCode, MAX_BROWSER_BYTES, Result, https_origin,
};
use std::{
    ffi::{CStr, c_char, c_int},
    ptr,
};
use url::Url;
use zeroize::Zeroizing;

pub struct BrowserCertificate {
    pub trusted: bool,
    pub changed_pin: bool,
    pub fingerprint: String,
    pub reason: String,
}

pub(crate) fn cstring(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() > MAX_BROWSER_BYTES || value.contains('\0') {
        return Err(Error::invalid("Invalid bounded native browser string"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    Ok(bytes)
}
fn output_string(bytes: &[c_char]) -> Result<String> {
    if !bytes.contains(&0) {
        return Err(Error::new(
            ErrorCode::ProtocolViolation,
            "Native browser output is not terminated",
        ));
    }
    unsafe { CStr::from_ptr(bytes.as_ptr()) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| {
            Error::new(
                ErrorCode::ProtocolViolation,
                "Native browser output is not UTF-8",
            )
        })
}

impl Engine {
    /// Synchronous; the temporary native context is created and freed on this thread.
    pub fn verify_browser_chain(
        &self,
        origin: &Url,
        chain: &[Vec<u8>],
        policy: &BrowserTlsPolicy,
    ) -> Result<BrowserCertificate> {
        if https_origin(origin.as_str())? != *origin || chain.is_empty() || chain.len() > 16 {
            return Err(Error::invalid("Invalid browser certificate scope or chain"));
        }
        let mut total = 0usize;
        for cert in chain {
            total = total
                .checked_add(cert.len())
                .ok_or_else(|| Error::invalid("Browser certificate chain exceeds limit"))?;
            if cert.is_empty() || total > MAX_BROWSER_BYTES {
                return Err(Error::invalid("Browser certificate chain exceeds limit"));
            }
        }
        let host = origin
            .host()
            .ok_or_else(|| Error::invalid("Browser certificate host missing"))?
            .to_string();
        let port = origin.port_or_known_default().unwrap_or(443);
        let pin = policy
            .pins
            .iter()
            .find(|pin| pin.host == host && pin.port == port);
        let pin_value = pin
            .map(|pin| {
                ocvpn_model::CertificatePin::new(&pin.host, pin.port, pin.fingerprint.clone())?;
                cstring(&pin.fingerprint)
            })
            .transpose()?;
        let name = cstring(host.trim_start_matches('[').trim_end_matches(']'))?;
        let ca = policy.ca_file.as_deref().map(cstring).transpose()?;
        let certificates: Vec<_> = chain
            .iter()
            .map(|der| abi::oc_cert {
                der_len: der.len() as c_int,
                der_data: der.as_ptr().cast_mut(),
                reserved: ptr::null_mut(),
            })
            .collect();
        let mut fingerprint = [0 as c_char; 128];
        let mut reason = [0 as c_char; 4096];
        let mut status = 0;
        let result = unsafe {
            self.native.ocgui_verify_browser_chain(
                certificates.as_ptr(),
                certificates.len() as u32,
                name.as_ptr().cast(),
                ca.as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr().cast()),
                pin_value
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr().cast()),
                fingerprint.as_mut_ptr(),
                fingerprint.len(),
                reason.as_mut_ptr(),
                reason.len(),
                &mut status,
            )
        };
        if result < 0 {
            return Err(Error::new(
                ErrorCode::CertificateRejected,
                "Browser certificate verification could not run; check the selected CA and certificate chain",
            ));
        }
        Ok(BrowserCertificate {
            trusted: result == 0,
            changed_pin: pin.is_some() && result != 0,
            fingerprint: output_string(&fingerprint)?,
            reason: output_string(&reason)?,
        })
    }
}

pub(crate) unsafe fn submit_page(
    native: &abi::OpenConnect,
    vpn: *mut abi::openconnect_info,
    page: BrowserPage,
    origin: &Url,
) -> Result<c_int> {
    page.validate(origin)?;
    let uri = cstring(page.uri.as_str())?;
    let cookies = page
        .cookies
        .iter()
        .flat_map(|(name, value)| [name, value])
        .map(|value| cstring(value.as_str()))
        .collect::<Result<Vec<_>>>()?;
    let headers = page
        .headers
        .iter()
        .flat_map(|(name, value)| [name, value])
        .map(|value| cstring(value.as_str()))
        .collect::<Result<Vec<_>>>()?;
    let mut cookie_pointers: Vec<*const c_char> =
        cookies.iter().map(|value| value.as_ptr().cast()).collect();
    let mut header_pointers: Vec<*const c_char> =
        headers.iter().map(|value| value.as_ptr().cast()).collect();
    cookie_pointers.push(ptr::null());
    header_pointers.push(ptr::null());
    let result = abi::oc_webview_result {
        uri: uri.as_ptr().cast(),
        cookies: cookie_pointers.as_mut_ptr(),
        headers: header_pointers.as_mut_ptr(),
    };
    Ok(unsafe { native.openconnect_webview_load_changed(vpn, &result) })
}
