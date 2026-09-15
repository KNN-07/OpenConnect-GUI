//! Privileged tunnel owner. Native pointers never leave the dedicated thread.
use crate::{Engine, abi};
use ocvpn_model::{AuthHandoff, Error, ErrorCode, Result, TrafficCounters};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub enum TunnelEvent {
    Statistics {
        traffic: TrafficCounters,
        tun_ready: bool,
        transport: String,
    },
    Reconnected,
    Finished(Result<()>),
}
struct Shared {
    native: Arc<abi::OpenConnect>,
    command: Mutex<Option<isize>>,
    cancelled: AtomicBool,
}
#[derive(Clone)]
pub struct TunnelControl(Arc<Shared>);
impl TunnelControl {
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.command(b'x');
    }
    pub fn request_statistics(&self) {
        self.command(b's');
    }
    fn command(&self, command: u8) {
        if let Some(handle) = *self.0.command.lock().unwrap_or_else(|e| e.into_inner()) {
            unsafe {
                self.0.native.ocgui_send_cmd(handle, command);
            }
        }
    }
}
pub struct TunnelTask {
    control: TunnelControl,
    events: Receiver<TunnelEvent>,
}
impl TunnelTask {
    pub fn control(&self) -> TunnelControl {
        self.control.clone()
    }
    pub fn try_recv(&self) -> Result<Option<TunnelEvent>> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(failure(
                "Native tunnel owner stopped without a terminal event",
            )),
        }
    }
}
impl Drop for TunnelTask {
    fn drop(&mut self) {
        self.control.cancel();
    }
}
impl Engine {
    /// The worker supplies only the two nonsecret transaction UUIDs. The helper
    /// location is fixed by the protected installation, never by IPC input.
    pub fn tunnel(
        &self,
        handoff: AuthHandoff,
        environment: Vec<(String, String)>,
    ) -> Result<TunnelTask> {
        handoff.validate(&self.capabilities.protocols, now())?;
        let shared = Arc::new(Shared {
            native: self.native.clone(),
            command: Mutex::new(None),
            cancelled: AtomicBool::new(false),
        });
        let control = TunnelControl(shared.clone());
        let (events_tx, events) = mpsc::sync_channel(32);
        let native = self.native.clone();
        std::thread::Builder::new()
            .name("ocvpn-tunnel".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut owner = Box::new(Owner {
                        progress: abi::ocgui_progress_context {
                            context: ptr::null_mut(),
                            callback: None,
                        },
                        native,
                        vpn: ptr::null_mut(),
                        handoff,
                        shared,
                        events: events_tx.clone(),
                    });
                    owner.run(environment)
                }))
                .unwrap_or_else(|_| Err(failure("Native tunnel owner panicked")));
                let _ = events_tx.send(TunnelEvent::Finished(result));
            })
            .map_err(|_| failure("Cannot start native tunnel owner"))?;
        Ok(TunnelTask { control, events })
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn failure(message: &str) -> Error {
    Error::new(ErrorCode::RuntimeFailure, message)
}
fn check(code: c_int, operation: &str) -> Result<()> {
    if code < 0 {
        Err(failure(operation))
    } else {
        Ok(())
    }
}
fn string(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() > 65536 || value.contains('\0') {
        return Err(Error::invalid("Invalid native tunnel input"));
    }
    let mut bytes = Zeroizing::new(value.as_bytes().to_vec());
    bytes.push(0);
    Ok(bytes)
}
fn set(
    vpn: *mut abi::openconnect_info,
    setter: unsafe extern "C" fn(*mut abi::openconnect_info, *const c_char) -> c_int,
    value: &str,
) -> Result<()> {
    let value = string(value)?;
    unsafe {
        check(
            setter(vpn, value.as_ptr().cast()),
            "Cannot configure native tunnel",
        )
    }
}
/// Fixed private helper; deployment must protect this file and its ancestors.
pub fn installed_helper() -> Result<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok("/usr/libexec/openconnect-gui/ocvpn-net".into())
    }
    #[cfg(target_os = "macos")]
    {
        Ok("/Applications/OpenConnect GUI.app/Contents/MacOS/ocvpn-net".into())
    }
    #[cfg(windows)]
    {
        Ok(crate::installed_native_directory()?
            .parent()
            .ok_or_else(|| failure("Invalid installation"))?
            .join("ocvpn-net.exe"))
    }
}
#[repr(C)]
struct Owner {
    progress: abi::ocgui_progress_context,
    native: Arc<abi::OpenConnect>,
    vpn: *mut abi::openconnect_info,
    handoff: AuthHandoff,
    shared: Arc<Shared>,
    events: SyncSender<TunnelEvent>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(handle) = self
            .shared
            .command
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            unsafe {
                self.native.ocgui_close_cmd_handle(handle);
            }
        }
        if !self.vpn.is_null() {
            unsafe {
                self.native.openconnect_vpninfo_free(self.vpn);
            }
        }
    }
}
impl Owner {
    fn run(&mut self, environment: Vec<(String, String)>) -> Result<()> {
        let context = self as *mut Self as *mut c_void;
        let n = &*self.native;
        unsafe {
            self.vpn = n.openconnect_vpninfo_new(
                c"OpenConnect GUI".as_ptr(),
                None,
                None,
                None,
                Some(n.ocgui_progress_bridge),
                context,
            );
            if self.vpn.is_null() {
                return Err(failure("Cannot allocate native tunnel"));
            }
            n.ocgui_set_peer_policy(self.vpn, Some(peer), context);
            n.openconnect_override_getaddrinfo(self.vpn, Some(resolve));
            n.openconnect_set_stats_handler(self.vpn, Some(stats));
            n.openconnect_set_reconnected_handler(self.vpn, Some(reconnected));
            n.openconnect_setup_cmd_pipe(self.vpn);
            let handle = n.ocgui_duplicate_cmd_handle(self.vpn);
            if handle == -1 {
                return Err(failure("Cannot create native tunnel command endpoint"));
            }
            *self
                .shared
                .command
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(handle);
        }
        if self.shared.cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        let v = self.vpn;
        let h = &self.handoff;
        set(v, n.openconnect_set_protocol, &h.protocol)?;
        set(v, n.openconnect_parse_url, h.connect_url.as_str())?;
        // Preserve the authentication DNS identity even when its selected peer is numeric.
        set(v, n.openconnect_set_hostname, &h.dns_name)?;
        unsafe {
            n.openconnect_set_system_trust(v, 0);
        }
        set(v, n.openconnect_set_cookie, &h.cookie)?;
        let o = &h.tunnel_options;
        for (value, setter) in [
            (&o.sni, n.openconnect_set_sni),
            (&o.user_agent, n.openconnect_set_useragent),
            (&o.reported_os, n.openconnect_set_reported_os),
        ] {
            if let Some(value) = value {
                set(v, setter, value)?;
            }
        }
        if let Some(proxy) = &o.proxy {
            let mut value = Zeroizing::new(proxy.as_str().to_owned());
            if let Some(credentials) = &h.proxy_credentials {
                #[derive(serde::Deserialize)]
                struct Part(#[serde(deserialize_with = "secret_part")] Zeroizing<String>);
                let [user, password]: [Part; 2] = serde_json::from_str(credentials)
                    .map_err(|_| Error::invalid("Invalid private proxy credentials"))?;
                for part in [&user.0, &password.0] {
                    if part.contains(['@', '/', '?', '#', '\\'])
                        || part.chars().any(char::is_control)
                    {
                        return Err(Error::invalid("Invalid encoded proxy credentials"));
                    }
                }
                let position = value
                    .find("://")
                    .ok_or_else(|| Error::invalid("Invalid proxy URL"))?
                    + 3;
                value.insert_str(position, "@");
                value.insert_str(position, &password.0);
                value.insert_str(position, ":");
                value.insert_str(position, &user.0);
            }
            set(v, n.openconnect_set_http_proxy, &value)?;
        }
        unsafe {
            if let Some(mtu) = o.mtu {
                n.openconnect_set_reqmtu(v, mtu.into());
            }
            if o.disable_ipv6 {
                check(n.openconnect_disable_ipv6(v), "Cannot disable IPv6")?;
            }
            if o.disable_dtls {
                check(
                    n.openconnect_disable_dtls(v),
                    "Cannot disable UDP transport",
                )?;
            }
            for (key, value) in environment {
                let key = string(&key)?;
                let value = string(&value)?;
                check(
                    n.ocgui_set_script_env(v, key.as_ptr().cast(), value.as_ptr().cast()),
                    "Invalid lifecycle transaction environment",
                )?;
            }
            let helper = installed_helper()?;
            let helper = helper
                .to_str()
                .ok_or_else(|| failure("Invalid helper installation path"))?;
            // Unix's shell needs quoting for the fixed macOS application name.
            #[cfg(unix)]
            let helper = string(&format!("\"{helper}\" </dev/null >/dev/null 2>/dev/null"))?;
            #[cfg(windows)]
            let helper = string(helper)?;
            check(
                n.ocgui_configure_tun(v, helper.as_ptr().cast(), ptr::null()),
                "Cannot configure fixed network helper",
            )?;
            check(
                n.openconnect_make_cstp_connection(v),
                "Cannot establish authenticated tunnel transport",
            )?;
            // Match the pinned CLI: UDP negotiation is optional; on setup failure
            // disable it so native reconnect does not retry a nonexistent channel.
            if !o.disable_dtls && n.openconnect_setup_dtls(v, 60) != 0 {
                check(
                    n.openconnect_disable_dtls(v),
                    "Cannot fall back to native TCP transport",
                )?;
            }
            let code = n.openconnect_mainloop(
                v,
                o.reconnect_timeout_secs
                    .try_into()
                    .map_err(|_| Error::invalid("Reconnect timeout exceeds native range"))?,
                abi::RECONNECT_INTERVAL_MIN as i32,
            );
            if self.shared.cancelled.load(Ordering::Acquire) || code == -4 || code == 0 {
                Ok(())
            } else if code == -1 {
                Err(Error::new(
                    ErrorCode::AuthenticationRequired,
                    "VPN authentication expired; authenticate again",
                ))
            } else {
                Err(failure(
                    "Native tunnel ended; check network connectivity and server policy",
                ))
            }
        }
    }
}
fn secret_part<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    <String as serde::Deserialize>::deserialize(d).map(Zeroizing::new)
}
unsafe extern "C" fn peer(context: *mut c_void, _: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let w = &*(context as *const Owner);
        let host =
            crate::native_text(w.native.openconnect_get_dnsname(w.vpn), 1024, "peer host").ok();
        if host.as_deref() != Some(w.handoff.dns_name.as_str())
            || w.native.openconnect_get_port(w.vpn)
                != i32::from(w.handoff.connect_url.port_or_known_default().unwrap_or(443))
        {
            return -1;
        }
        let Ok(pin) = CString::new(w.handoff.peer_fingerprint.as_str()) else {
            return -1;
        };
        w.native
            .openconnect_check_peer_cert_hash(w.vpn, pin.as_ptr())
    }))
    .unwrap_or(-1)
}
unsafe extern "C" fn resolve(
    context: *mut c_void,
    node: *const c_char,
    service: *const c_char,
    hints: *const abi::addrinfo,
    result: *mut *mut abi::addrinfo,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let w = &*(context as *const Owner);
        let host = crate::native_text(node, 1024, "resolver host").ok();
        if host.as_deref() == Some(w.handoff.dns_name.as_str())
            && w.handoff.tunnel_options.proxy.is_none()
        {
            if let Some(address) = w.handoff.peer_address {
                if let Ok(address) = CString::new(address.to_string()) {
                    return w.native.ocgui_getaddrinfo_numeric(
                        address.as_ptr(),
                        service,
                        hints,
                        result,
                    );
                }
            }
        }
        w.native
            .ocgui_getaddrinfo_system(node, service, hints, result)
    }))
    .unwrap_or(-1)
}
unsafe extern "C" fn stats(context: *mut c_void, stats: *const abi::oc_stats) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let w = &*(context as *const Owner);
        if stats.is_null() {
            return;
        }
        let transport = if w.native.ocgui_transport_is_udp(w.vpn) != 0 {
            "udp"
        } else {
            "tcp"
        }
        .to_owned();
        let _ = w.events.try_send(TunnelEvent::Statistics {
            traffic: TrafficCounters {
                rx_bytes: (*stats).rx_bytes,
                tx_bytes: (*stats).tx_bytes,
            },
            tun_ready: w.native.ocgui_tun_is_up(w.vpn) != 0,
            transport,
        });
    }));
}
unsafe extern "C" fn reconnected(context: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let w = &*(context as *const Owner);
        if w.events.try_send(TunnelEvent::Reconnected).is_err() {
            w.shared.cancelled.store(true, Ordering::Release);
            if let Some(handle) = *w.shared.command.lock().unwrap_or_else(|e| e.into_inner()) {
                w.native.ocgui_send_cmd(handle, b'x');
            }
        }
    }));
}
