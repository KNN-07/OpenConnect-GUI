//! Public LaunchServices and AppleEvent Mach APIs, without AppKit/HIToolbox.
//! The callback executable must enter this module before initializing either UI toolkit.
use ocvpn_model::{Error, ErrorCode, Result, SecretText};
use std::{
    ffi::{CStr, c_void},
    path::Path,
    ptr,
    time::Duration,
};
use zeroize::Zeroizing;

pub(super) const HANDLER: &str = "org.openconnectgui.callback";
const BUNDLE: &str = "/Applications/OpenConnect GUI.app/Contents/Helpers/OpenConnect Callback.app";
const SCHEME: &str = "globalprotectcallback";
const UTF8: u32 = 0x08000100;
const GET_URL: u32 = u32::from_be_bytes(*b"GURL");
const LIMIT: usize = 1024 * 1024;
type Ref = *const c_void;
type EventHandler = unsafe extern "C" fn(*const c_void, *mut c_void, isize) -> i16;

fn unavailable() -> Error {
    Error::new(
        ErrorCode::AuthenticationRequired,
        "macOS browser activation or callback delivery failed; use manual authentication or check the installed callback application",
    )
}
fn conflict() -> Error {
    Error::new(
        ErrorCode::Busy,
        "Another application handles GlobalProtect callbacks; explicit replacement consent is required",
    )
}

// SDK LSOpen.h uses two-byte structure packing, including on 64-bit macOS.
#[repr(C, packed(2))]
struct LaunchSpec {
    app: Ref,
    items: Ref,
    params: Ref,
    flags: u32,
    context: *mut c_void,
}
#[repr(C)]
struct MachContext {
    version: isize,
    info: *mut c_void,
    retain: Ref,
    release: Ref,
    description: Ref,
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSOpenFromURLSpec(spec: *const LaunchSpec, launched: *mut Ref) -> i32;
    fn LSCopyDefaultApplicationURLForURL(url: Ref, roles: u32, error: *mut Ref) -> Ref;
    fn LSSetDefaultHandlerForURLScheme(scheme: Ref, handler: Ref) -> i32;
    fn LSRegisterURL(url: Ref, update: u8) -> i32;
    fn AEGetRegisteredMachPort() -> u32;
    fn AEProcessMessage(message: *mut c_void) -> i32;
    fn AEInstallEventHandler(
        class: u32,
        id: u32,
        handler: EventHandler,
        context: isize,
        system: u8,
    ) -> i16;
    fn AERemoveEventHandler(class: u32, id: u32, handler: EventHandler, system: u8) -> i16;
    fn AEGetParamPtr(
        event: *const c_void,
        key: u32,
        desired: u32,
        actual: *mut u32,
        data: *mut c_void,
        capacity: i32,
        size: *mut i32,
    ) -> i16;
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
    fn CFStringGetCString(value: Ref, buffer: *mut i8, size: isize, encoding: u32) -> u8;
    fn CFURLCreateWithBytes(
        allocator: Ref,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        base: Ref,
    ) -> Ref;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: Ref,
        bytes: *const u8,
        length: isize,
        directory: u8,
    ) -> Ref;
    fn CFURLGetFileSystemRepresentation(url: Ref, resolve: u8, buffer: *mut u8, size: isize) -> u8;
    fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
    fn CFBundleCreate(allocator: Ref, url: Ref) -> Ref;
    fn CFBundleGetIdentifier(bundle: Ref) -> Ref;
    fn CFErrorGetCode(error: Ref) -> isize;
    fn CFMachPortCreateWithPort(
        allocator: Ref,
        port: u32,
        callback: unsafe extern "C" fn(Ref, *mut c_void, isize, *mut c_void),
        context: *mut MachContext,
        free_info: *mut u8,
    ) -> Ref;
    fn CFMachPortCreateRunLoopSource(allocator: Ref, port: Ref, order: isize) -> Ref;
    fn CFMachPortInvalidate(port: Ref);
    fn CFRunLoopGetCurrent() -> Ref;
    fn CFRunLoopAddSource(run_loop: Ref, source: Ref, mode: Ref);
    fn CFRunLoopRemoveSource(run_loop: Ref, source: Ref, mode: Ref);
    fn CFRunLoopRunInMode(mode: Ref, seconds: f64, return_after_source: u8) -> i32;
    fn CFRunLoopStop(run_loop: Ref);
    static kCFRunLoopDefaultMode: Ref;
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
        unsafe { CFRelease(self.0) }
    }
}
fn string(value: &str) -> Result<Owned> {
    Owned::new(unsafe {
        CFStringCreateWithBytes(ptr::null(), value.as_ptr(), value.len() as isize, UTF8, 0)
    })
}
fn url(value: &str) -> Result<Owned> {
    Owned::new(unsafe {
        CFURLCreateWithBytes(
            ptr::null(),
            value.as_ptr(),
            value.len() as isize,
            UTF8,
            ptr::null(),
        )
    })
}
fn file_url(value: &str) -> Result<Owned> {
    Owned::new(unsafe {
        CFURLCreateFromFileSystemRepresentation(
            ptr::null(),
            value.as_ptr(),
            value.len() as isize,
            1,
        )
    })
}
fn text(value: Ref) -> Result<String> {
    if value.is_null() {
        return Err(unavailable());
    }
    let mut buffer = [0i8; 4096];
    if unsafe { CFStringGetCString(value, buffer.as_mut_ptr(), buffer.len() as isize, UTF8) } == 0 {
        return Err(unavailable());
    }
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| unavailable())
}

pub(super) async fn launch(uri: &str) -> Result<()> {
    // Only the non-credential loopback bootstrap reaches LaunchServices. Never invoke /usr/bin/open.
    let uri = uri.to_owned();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            let target = url(&uri)?;
            // NULL callbacks are safe: target outlives this non-retaining array and the LS call.
            let items =
                Owned::new(unsafe { CFArrayCreate(ptr::null(), &target.0, 1, ptr::null()) })?;
            let spec = LaunchSpec {
                app: ptr::null(),
                items: items.0,
                params: ptr::null(),
                flags: 0x00010000 | 0x00000100,
                context: ptr::null_mut(),
            };
            // LSOpenFromURLSpec is thread-safe since 10.2; async avoids waiting for browser startup.
            if unsafe { LSOpenFromURLSpec(&spec, ptr::null_mut()) } != 0 {
                return Err(unavailable());
            }
            Ok(())
        }),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())?
}

pub(super) fn association() -> Result<Option<String>> {
    let target = url("globalprotectcallback:")?;
    let mut error = ptr::null();
    let application = unsafe { LSCopyDefaultApplicationURLForURL(target.0, u32::MAX, &mut error) };
    let error = if error.is_null() {
        None
    } else {
        Some(Owned(error))
    };
    if application.is_null() {
        return if error
            .as_ref()
            .is_some_and(|e| unsafe { CFErrorGetCode(e.0) } == -10814)
        {
            Ok(None)
        } else {
            Err(unavailable())
        };
    }
    let application = Owned(application);
    let bundle = Owned::new(unsafe { CFBundleCreate(ptr::null(), application.0) })?;
    let identifier = text(unsafe { CFBundleGetIdentifier(bundle.0) })?;
    if identifier == HANDLER {
        let mut path = [0u8; 4096];
        if unsafe {
            CFURLGetFileSystemRepresentation(
                application.0,
                1,
                path.as_mut_ptr(),
                path.len() as isize,
            )
        } == 0
        {
            return Err(unavailable());
        }
        let actual = unsafe { CStr::from_ptr(path.as_ptr().cast()) }
            .to_str()
            .map_err(|_| unavailable())?;
        // A same-ID bundle elsewhere is not our installed receiver.
        if actual.trim_end_matches('/') != BUNDLE {
            return Ok(Some(format!("{identifier} (different installation)")));
        }
    }
    Ok(Some(identifier))
}

pub(super) fn register(replace_existing: bool) -> Result<()> {
    let existing = association()?;
    if existing.as_deref().is_some_and(|id| id != HANDLER) && !replace_existing {
        return Err(conflict());
    }
    // Verify the installed executable and its ancestry, not a caller-selected application.
    super::installed_callback()?;
    let bundle = file_url(BUNDLE)?;
    let bundle_info = Owned::new(unsafe { CFBundleCreate(ptr::null(), bundle.0) })?;
    if text(unsafe { CFBundleGetIdentifier(bundle_info.0) })? != HANDLER {
        return Err(unavailable());
    }
    let scheme = string(SCHEME)?;
    let handler = string(HANDLER)?;
    // Registration is only reached through an explicit user operation.
    if unsafe { LSRegisterURL(bundle.0, 1) } != 0 {
        return Err(unavailable());
    }
    // Recheck immediately before changing the default; LaunchServices offers no atomic CAS.
    let current = association()?;
    if current != existing && current.as_deref() != Some(HANDLER) && !replace_existing {
        return Err(conflict());
    }
    if unsafe { LSSetDefaultHandlerForURLScheme(scheme.0, handler.0) } != 0 {
        return Err(unavailable());
    }
    if association()?.as_deref() != Some(HANDLER) {
        return Err(unavailable());
    }
    Ok(())
}

struct Receiver {
    run_loop: Ref,
    result: Option<Result<SecretText>>,
}
unsafe extern "C" fn receive(event: *const c_void, _: *mut c_void, context: isize) -> i16 {
    // Only this dedicated main-thread CFRunLoop invokes the handler, with a live stack context.
    let state = unsafe { &mut *(context as *mut Receiver) };
    if state.result.is_some() {
        return -1708;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut buffer = Zeroizing::new(vec![0u8; LIMIT]);
        let mut length = 0i32;
        let status = unsafe {
            AEGetParamPtr(
                event,
                u32::from_be_bytes(*b"----"),
                u32::from_be_bytes(*b"utf8"),
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                LIMIT as i32,
                &mut length,
            )
        };
        if status != 0 || length <= 0 || length as usize > LIMIT {
            return Err(unavailable());
        }
        let uri = std::str::from_utf8(&buffer[..length as usize]).map_err(|_| unavailable())?;
        if !uri.starts_with("globalprotectcallback:") || uri.contains('\0') {
            return Err(unavailable());
        }
        Ok(SecretText::new(uri.to_owned()))
    }))
    .unwrap_or_else(|_| Err(unavailable()));
    let status = if result.is_ok() { 0 } else { -1700 };
    state.result = Some(result);
    unsafe { CFRunLoopStop(state.run_loop) };
    status
}
unsafe extern "C" fn dispatch(_: Ref, message: *mut c_void, _: isize, context: *mut c_void) {
    let result = std::panic::catch_unwind(|| unsafe { AEProcessMessage(message) });
    if result.is_err() {
        let state = unsafe { &mut *context.cast::<Receiver>() };
        state.result = Some(Err(unavailable()));
        unsafe { CFRunLoopStop(state.run_loop) };
    }
}
struct InstalledHandler;
impl Drop for InstalledHandler {
    fn drop(&mut self) {
        unsafe {
            AERemoveEventHandler(GET_URL, GET_URL, receive, 0);
        }
    }
}
struct Source {
    run_loop: Ref,
    port: Owned,
    source: Owned,
}
impl Drop for Source {
    fn drop(&mut self) {
        unsafe {
            CFRunLoopRemoveSource(self.run_loop, self.source.0, kCFRunLoopDefaultMode);
            CFMachPortInvalidate(self.port.0);
        }
    }
}

pub(super) fn run_callback_receiver() -> Result<()> {
    // This executable must not share the registered AE Mach port with AppKit/HIToolbox.
    if unsafe { libc::pthread_main_np() } == 0 || tokio::runtime::Handle::try_current().is_ok() {
        return Err(unavailable());
    }
    let mut receiver = Receiver {
        run_loop: unsafe { CFRunLoopGetCurrent() },
        result: None,
    };
    let context = (&mut receiver as *mut Receiver).cast::<c_void>();
    if unsafe { AEInstallEventHandler(GET_URL, GET_URL, receive, context as isize, 0) } != 0 {
        return Err(unavailable());
    }
    let handler = InstalledHandler;
    // The AE port queues launch events until our source is installed: no startup event race.
    let native_port = unsafe { AEGetRegisteredMachPort() };
    if native_port == 0 {
        return Err(unavailable());
    }
    let mut mach_context = MachContext {
        version: 0,
        info: context,
        retain: ptr::null(),
        release: ptr::null(),
        description: ptr::null(),
    };
    let port = Owned::new(unsafe {
        CFMachPortCreateWithPort(
            ptr::null(),
            native_port,
            dispatch,
            &mut mach_context,
            ptr::null_mut(),
        )
    })?;
    let source = Owned::new(unsafe { CFMachPortCreateRunLoopSource(ptr::null(), port.0, 0) })?;
    let source = Source {
        run_loop: receiver.run_loop,
        port,
        source,
    };
    unsafe {
        CFRunLoopAddSource(receiver.run_loop, source.source.0, kCFRunLoopDefaultMode);
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 10.0, 0);
    }
    // No further AppleEvent can access receiver while we forward through private owner IPC.
    drop(source);
    drop(handler);
    let uri = receiver.result.ok_or_else(unavailable)??;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| unavailable())?;
    runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                crate::browser::submit_callback(uri),
            )
            .await
            .map_err(|_| unavailable())?
        })
        .map_err(|_| unavailable())
}
