//! Per-query authentication policy; never toggles process-wide keychain UI state.
use super::{SERVICE, unavailable};
use ocvpn_model::Result;
use std::{ffi::c_void, ptr};
use zeroize::Zeroizing;
type Ref = *const c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainCopyDomainDefault(domain: u32, keychain: *mut Ref) -> i32;
    fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> i32;
    fn SecItemUpdate(query: Ref, attributes: Ref) -> i32;
    fn SecItemAdd(attributes: Ref, result: *mut Ref) -> i32;
    static kSecClass: Ref;
    static kSecClassGenericPassword: Ref;
    static kSecAttrService: Ref;
    static kSecAttrAccount: Ref;
    static kSecMatchSearchList: Ref;
    static kSecUseKeychain: Ref;
    static kSecMatchLimit: Ref;
    static kSecMatchLimitOne: Ref;
    static kSecReturnData: Ref;
    static kSecValueData: Ref;
    static kSecUseAuthenticationUI: Ref;
    static kSecUseAuthenticationUIFail: Ref;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Ref);
    fn CFStringCreateWithBytes(
        allocator: Ref,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> Ref;
    fn CFArrayCreate(allocator: Ref, values: *const Ref, length: isize, callbacks: Ref) -> Ref;
    fn CFDictionaryCreate(
        allocator: Ref,
        keys: *const Ref,
        values: *const Ref,
        length: isize,
        keys_callbacks: Ref,
        values_callbacks: Ref,
    ) -> Ref;
    fn CFDataCreate(allocator: Ref, bytes: *const u8, length: isize) -> Ref;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFDataGetBytePtr(data: Ref) -> *const u8;
    static kCFBooleanTrue: Ref;
}
struct Owned(Ref);
impl Owned {
    fn new(value: Ref) -> Result<Self> {
        if value.is_null() {
            Err(unavailable())
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.0);
        }
    }
}
fn string(value: &str) -> Result<Owned> {
    Owned::new(unsafe {
        CFStringCreateWithBytes(
            ptr::null(),
            value.as_ptr(),
            value.len() as isize,
            0x08000100,
            0,
        )
    })
}
fn dictionary(entries: &[(Ref, Ref)]) -> Result<Owned> {
    let keys: Vec<_> = entries.iter().map(|entry| entry.0).collect();
    let values: Vec<_> = entries.iter().map(|entry| entry.1).collect();
    // Borrowed constant keys and owned values stay alive for the entire native call.
    Owned::new(unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            entries.len() as isize,
            ptr::null(),
            ptr::null(),
        )
    })
}
fn access(account: &str, value: Option<&str>) -> Result<Option<Zeroizing<String>>> {
    let mut keychain = ptr::null();
    if unsafe { SecKeychainCopyDomainDefault(0, &mut keychain) } != 0 {
        return Err(unavailable());
    }
    let keychain = Owned::new(keychain)?;
    let search = Owned::new(unsafe { CFArrayCreate(ptr::null(), &keychain.0, 1, ptr::null()) })?;
    let service = string(SERVICE)?;
    let account = string(account)?;
    let mut entries = unsafe {
        vec![
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service.0),
            (kSecAttrAccount, account.0),
            (kSecMatchSearchList, search.0),
            (kSecUseAuthenticationUI, kSecUseAuthenticationUIFail),
        ]
    };
    if let Some(value) = value {
        let data =
            Owned::new(unsafe { CFDataCreate(ptr::null(), value.as_ptr(), value.len() as isize) })?;
        let query = dictionary(&entries)?;
        let attributes = dictionary(&[(unsafe { kSecValueData }, data.0)])?;
        let mut status = unsafe { SecItemUpdate(query.0, attributes.0) };
        if status == -25300 {
            entries.retain(|entry| entry.0 != unsafe { kSecMatchSearchList });
            entries.push((unsafe { kSecUseKeychain }, keychain.0));
            entries.push((unsafe { kSecValueData }, data.0));
            let attributes = dictionary(&entries)?;
            status = unsafe { SecItemAdd(attributes.0, ptr::null_mut()) };
        }
        if status != 0 {
            return Err(unavailable());
        }
        return Ok(None);
    }
    entries.push(unsafe { (kSecReturnData, kCFBooleanTrue) });
    entries.push(unsafe { (kSecMatchLimit, kSecMatchLimitOne) });
    let query = dictionary(&entries)?;
    let mut result = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.0, &mut result) };
    if status == -25300 {
        return Ok(None);
    }
    if status != 0 {
        return Err(unavailable());
    }
    let data = Owned::new(result)?;
    let length = unsafe { CFDataGetLength(data.0) };
    if !(0..=65536).contains(&length) {
        return Err(unavailable());
    }
    if length == 0 {
        return Ok(Some(Zeroizing::new(String::new())));
    }
    let bytes = unsafe { CFDataGetBytePtr(data.0) };
    if bytes.is_null() {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(unsafe { std::slice::from_raw_parts(bytes, length as usize) })
        .map_err(|_| unavailable())?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}
pub(super) fn read(account: &str) -> Result<Option<Zeroizing<String>>> {
    access(account, None)
}
pub(super) fn write(account: &str, value: &str) -> Result<()> {
    access(account, Some(value)).map(|_| ())
}
