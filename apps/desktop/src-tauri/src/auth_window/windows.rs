//! WebView2 objects and deferrals never leave the owning GUI STA.
//! ServerCertificateErrorDetected observes failed chains only. Saved strict pins
//! cannot be enforced by this API; reject those requests rather than weaken TLS.
use base64::Engine as _;
use ocvpn_model::{
    BrowserCertificateChallenge, BrowserClientMessage, BrowserPage, BrowserRequest, Error,
    ErrorCode, MAX_BROWSER_BYTES, NativeBrowserKind, Result, SecretText, https_origin,
};
use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc};
use tauri::WebviewWindow;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;
use webview2_com::{Microsoft::Web::WebView2::Win32::*, *};
use windows::{
    Win32::System::Com::CoTaskMemFree,
    core::{BOOL, HSTRING, Interface, PWSTR},
};

type NativeResult<T> = windows::core::Result<T>;
type Pairs = Vec<(SecretText, SecretText)>;
thread_local! { static VIEWS: RefCell<HashMap<String, Rc<RefCell<View>>>> = RefCell::new(HashMap::new()); }
struct Pending {
    args: ICoreWebView2ServerCertificateErrorDetectedEventArgs,
    deferral: ICoreWebView2Deferral,
    generation: u64,
    completed: bool,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if !self.completed {
            unsafe {
                let _ = self
                    .args
                    .SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL);
                let _ = self.deferral.Complete();
            }
        }
    }
}
struct View {
    web: ICoreWebView2,
    controller: ICoreWebView2Controller,
    request: Arc<BrowserRequest>,
    sender: Sender<BrowserClientMessage>,
    window: WebviewWindow,
    generation: u64,
    navigation_id: u64,
    uri: Option<SecretText>,
    headers: Pairs,
    pending: HashMap<Uuid, Pending>,
    tokens: Vec<(u8, i64)>,
    closed: bool,
    capturing: bool,
    loaded: bool,
}
fn native_error() -> windows::core::Error {
    windows::core::Error::from_hresult(windows::core::HRESULT(0x80004005u32 as i32))
}
fn adapter_error() -> Error {
    Error::new(
        ErrorCode::UnsupportedAuthentication,
        "WebView2 authentication failed; update WebView2 or use system/manual authentication",
    )
}

// WebView2 owns the returned allocation. Bound the UTF-16 scan before copying;
// native error text and raw payloads must never enter diagnostics.
fn text(get: impl FnOnce(*mut PWSTR) -> NativeResult<()>) -> NativeResult<SecretText> {
    let mut ptr = PWSTR::null();
    let result = get(&mut ptr);
    let value = (|| {
        result?;
        if ptr.is_null() {
            return Ok(SecretText::new(String::new()));
        }
        let mut len = 0;
        unsafe {
            while len <= MAX_BROWSER_BYTES && *ptr.0.add(len) != 0 {
                len += 1;
            }
            if len > MAX_BROWSER_BYTES {
                return Err(native_error());
            }
            let value = String::from_utf16(std::slice::from_raw_parts(ptr.0, len))
                .map_err(|_| native_error())?;
            if value.len() > MAX_BROWSER_BYTES {
                return Err(native_error());
            }
            Ok(SecretText::new(value))
        }
    })();
    unsafe {
        CoTaskMemFree(Some(ptr.0.cast()));
    }
    value
}
fn source(web: &ICoreWebView2) -> NativeResult<SecretText> {
    text(|out| unsafe { web.Source(out) })
}
fn current(view: &View, generation: u64, uri: &str) -> bool {
    !view.closed
        && view.generation == generation
        && source(&view.web).is_ok_and(|value| value.as_str() == uri)
        && https_origin(uri).is_ok_and(|origin| origin == view.request.expected_origin)
}
fn allowed(view: &mut View, uri: &str, initialization: bool) -> bool {
    if initialization && uri == "about:blank" && view.generation == 0 {
        return true;
    }
    if uri == view.request.uri.as_str() {
        return true;
    }
    if view.request.kind == NativeBrowserKind::External {
        if let Ok(url) = url::Url::parse(uri) {
            if url.scheme() == "http"
                && url.host_str() == Some("[::1]")
                && url.port() == Some(29786)
                && url.username().is_empty()
                && url.password().is_none()
            {
                return true;
            }
        }
    }
    https_origin(uri).is_ok()
}
fn fail(view: &Rc<RefCell<View>>) {
    let window = {
        let mut view = view.borrow_mut();
        if view.closed {
            return;
        }
        view.closed = true;
        let _ = view.sender.try_send(BrowserClientMessage::Failed {
            transaction_id: view.request.transaction_id,
            error: adapter_error(),
        });
        unsafe {
            let _ = view.web.Stop();
        }
        view.window.clone()
    };
    super::defer_close(window);
}
fn emit(view: &Rc<RefCell<View>>, message: BrowserClientMessage) {
    if view.borrow().sender.try_send(message).is_err() {
        fail(view);
    }
}
fn pem_der(pem: &str) -> NativeResult<Vec<u8>> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|s| s.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or_else(native_error)?;
    if body.len() > 128 * 1024 {
        return Err(native_error());
    }
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| native_error())?;
    if der.is_empty() {
        return Err(native_error());
    }
    Ok(der)
}
fn certificate_chain(
    args: &ICoreWebView2ServerCertificateErrorDetectedEventArgs,
) -> NativeResult<Vec<Vec<u8>>> {
    unsafe {
        let certificate = args.ServerCertificate()?;
        let leaf = text(|p| certificate.ToPemEncoding(p))?;
        let mut chain = vec![pem_der(leaf.as_str())?];
        let issuers = certificate.PemEncodedIssuerCertificateChain()?;
        let mut count = 0;
        issuers.Count(&mut count)?;
        if count > 15 {
            return Err(native_error());
        }
        let mut bytes = chain[0].len();
        for i in 0..count {
            let pem = text(|p| issuers.GetValueAtIndex(i, p))?;
            let der = pem_der(pem.as_str())?;
            // WebView2's collection includes the current leaf at index zero.
            if i == 0 && der == chain[0] {
                continue;
            }
            bytes += der.len();
            if bytes > 512 * 1024 {
                return Err(native_error());
            }
            chain.push(der);
        }
        Ok(chain)
    }
}
fn headers(response: &ICoreWebView2WebResourceResponseView) -> NativeResult<Pairs> {
    unsafe {
        let iterator = response.Headers()?.GetIterator()?;
        let mut more = BOOL(0);
        iterator.HasCurrentHeader(&mut more)?;
        let mut pairs = Vec::new();
        let mut bytes = 0;
        while more.as_bool() {
            if pairs.len() == 128 {
                return Err(native_error());
            }
            let mut value = PWSTR::null();
            let name = text(|p| iterator.GetCurrentHeader(p, &mut value));
            let value = text(|p| {
                *p = value;
                Ok(())
            })?;
            let name = name?;
            bytes += name.as_str().len() + value.as_str().len();
            if bytes > 256 * 1024 {
                return Err(native_error());
            }
            pairs.push((name, value));
            iterator.MoveNext(&mut more)?;
        }
        Ok(pairs)
    }
}
fn capture(view: &Rc<RefCell<View>>) -> NativeResult<()> {
    let (web, generation, uri) = {
        let mut v = view.borrow_mut();
        if v.closed || v.capturing || !v.loaded {
            return Ok(());
        }
        let uri = source(&v.web)?;
        if !current(&v, v.generation, uri.as_str()) {
            return Ok(());
        }
        v.capturing = true;
        (v.web.clone(), v.generation, uri)
    };
    // Fixed extraction, not a page-to-app messaging bridge. Limit the DOM before
    // WebView2 serializes it. A null result is an explicit oversized-page error.
    let script = HSTRING::from(
        "(()=>{let s='';for(const n of document.childNodes){if(n.nodeType===10)continue;s+=new XMLSerializer().serializeToString(n);if(s.length>196608)return null;}return s;})()",
    );
    let weak = Rc::downgrade(view);
    let callback = ExecuteScriptCompletedHandler::create(Box::new(move |result, json| {
        let json = SecretText::new(json);
        let Some(view) = weak.upgrade() else {
            return Ok(());
        };
        if !current(&view.borrow(), generation, uri.as_str()) {
            view.borrow_mut().capturing = false;
            if capture(&view).is_err() {
                fail(&view);
            }
            return Ok(());
        }
        let document = if result.is_ok() && json.as_str().len() <= MAX_BROWSER_BYTES {
            serde_json::from_str::<String>(json.as_str())
                .ok()
                .filter(|s| s.len() <= 768 * 1024)
        } else {
            None
        };
        let Some(document) = document else {
            fail(&view);
            return Ok(());
        };
        let document = SecretText::new(document);
        let web = view.borrow().web.clone();
        let manager = match unsafe { web.cast::<ICoreWebView2_2>()?.CookieManager() } {
            Ok(manager) => manager,
            Err(_) => {
                fail(&view);
                return Ok(());
            }
        };
        let cookie_uri = HSTRING::from(uri.as_str());
        let weak = Rc::downgrade(&view);
        let callback = GetCookiesCompletedHandler::create(Box::new(move |result, list| {
            let Some(view) = weak.upgrade() else {
                return Ok(());
            };
            if !current(&view.borrow(), generation, uri.as_str()) {
                view.borrow_mut().capturing = false;
                if capture(&view).is_err() {
                    fail(&view);
                }
                return Ok(());
            }
            let result = (|| unsafe {
                result?;
                let list = list.ok_or_else(native_error)?;
                let mut count = 0;
                list.Count(&mut count)?;
                if count > 128 {
                    return Err(native_error());
                }
                let mut cookies = Vec::with_capacity(count as usize);
                let mut bytes = 0;
                for index in 0..count {
                    let cookie = list.GetValueAtIndex(index)?;
                    let name = text(|p| cookie.Name(p))?;
                    let value = text(|p| cookie.Value(p))?;
                    bytes += name.as_str().len() + value.as_str().len();
                    if bytes > 256 * 1024 {
                        return Err(native_error());
                    }
                    cookies.push((name, value));
                }
                Ok(cookies)
            })();
            let Ok(cookies) = result else {
                fail(&view);
                return Ok(());
            };
            let message = {
                let mut v = view.borrow_mut();
                v.capturing = false;
                let page = BrowserPage {
                    uri,
                    cookies,
                    headers: std::mem::take(&mut v.headers),
                    document: Some(document),
                };
                if page.validate(&v.request.expected_origin).is_err() {
                    drop(v);
                    fail(&view);
                    return Ok(());
                }
                BrowserClientMessage::Page {
                    transaction_id: v.request.transaction_id,
                    page,
                }
            };
            emit(&view, message);
            Ok(())
        }));
        if unsafe { manager.GetCookies(&cookie_uri, &callback) }.is_err() {
            fail(&view);
        }
        Ok(())
    }));
    unsafe { web.ExecuteScript(&script, &callback) }
}

pub(super) fn attach(
    window: &WebviewWindow,
    request: Arc<BrowserRequest>,
    sender: Sender<BrowserClientMessage>,
) -> Result<()> {
    if !request.tls.pins.is_empty() {
        return Err(Error::new(
            ErrorCode::UnsupportedAuthentication,
            "WebView2 cannot enforce saved certificate pins on system-trusted chains; use manual or system authentication with explicit browser trust policy",
        ));
    }
    let owned = window.clone();
    window
        .with_webview(move |native| {
            let result = (|| unsafe {
                let controller = native.controller();
                let web = controller.CoreWebView2()?;
                if !matches!(source(&web)?.as_str(), "" | "about:blank") {
                    return Err(native_error());
                }
                let profile = web.cast::<ICoreWebView2_13>()?.Profile()?;
                let mut private = BOOL(0);
                profile.IsInPrivateModeEnabled(&mut private)?;
                if !private.as_bool() {
                    return Err(native_error());
                }
                // Unique data_directory is established by the coordinator. Verify its
                // transaction component in the actual native profile path as well.
                let path = text(|p| profile.ProfilePath(p))?;
                if !std::path::Path::new(path.as_str())
                    .components()
                    .any(|p| p.as_os_str() == request.transaction_id.to_string().as_str())
                {
                    return Err(native_error());
                }
                let settings = web.Settings()?;
                settings.SetIsWebMessageEnabled(false)?;
                settings.SetAreHostObjectsAllowed(false)?;
                settings.SetAreDevToolsEnabled(false)?;
                settings.SetAreDefaultContextMenusEnabled(false)?;
                let view = Rc::new(RefCell::new(View {
                    web,
                    controller,
                    request: request.clone(),
                    sender: sender.clone(),
                    window: owned.clone(),
                    generation: 0,
                    navigation_id: 0,
                    uri: None,
                    headers: Vec::new(),
                    pending: HashMap::new(),
                    tokens: Vec::new(),
                    closed: false,
                    capturing: false,
                    loaded: false,
                }));
                VIEWS.with(|views| {
                    views
                        .borrow_mut()
                        .insert(owned.label().to_owned(), view.clone())
                });
                install(&view)?;
                let polling = owned.clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        let (answer, wait) = tokio::sync::oneshot::channel();
                        let label = polling.label().to_owned();
                        if polling
                            .run_on_main_thread(move || {
                                let active =
                                    VIEWS.with(|views| views.borrow().get(&label).cloned());
                                let keep =
                                    active.as_ref().is_some_and(|view| !view.borrow().closed);
                                if let Some(view) = active {
                                    if capture(&view).is_err() {
                                        fail(&view);
                                    }
                                }
                                let _ = answer.send(keep);
                            })
                            .is_err()
                        {
                            break;
                        }
                        if wait.await != Ok(true) {
                            break;
                        }
                    }
                });
                super::attached(&request, &sender).map_err(|_| native_error())?;
                Ok(())
            })();
            if result.is_err() {
                let _ = sender.try_send(BrowserClientMessage::Failed {
                    transaction_id: request.transaction_id,
                    error: adapter_error(),
                });
                super::defer_close(owned.clone());
            }
        })
        .map_err(|_| adapter_error())
}

fn install(view: &Rc<RefCell<View>>) -> NativeResult<()> {
    let web = view.borrow().web.clone();
    unsafe {
        let weak = Rc::downgrade(view);
        let starting = NavigationStartingEventHandler::create(Box::new(move |_, args| {
            let Some(view) = weak.upgrade() else {
                return Ok(());
            };
            let Some(args) = args else {
                fail(&view);
                return Ok(());
            };
            let result = (|| {
                let uri = text(|p| args.Uri(p))?;
                let mut v = view.borrow_mut();
                if v.closed || !allowed(&mut v, uri.as_str(), true) {
                    args.SetCancel(true)?;
                    return Ok(());
                }
                args.NavigationId(&mut v.navigation_id)?;
                v.generation = v.generation.checked_add(1).ok_or_else(native_error)?;
                v.uri = Some(uri);
                v.headers.clear();
                v.pending.clear();
                v.loaded = false;
                Ok(())
            })();
            if result.is_err() {
                let _ = args.SetCancel(true);
                fail(&view);
            }
            Ok(())
        }));
        let mut token = 0;
        web.add_NavigationStarting(&starting, &mut token)?;
        view.borrow_mut().tokens.push((0, token));

        let weak = Rc::downgrade(view);
        let completed = NavigationCompletedEventHandler::create(Box::new(move |_, args| {
            let Some(view) = weak.upgrade() else {
                return Ok(());
            };
            let Some(args) = args else {
                fail(&view);
                return Ok(());
            };
            let mut success = BOOL(0);
            let mut id = 0;
            let result = (|| {
                args.IsSuccess(&mut success)?;
                args.NavigationId(&mut id)?;
                if success.as_bool() && id == view.borrow().navigation_id {
                    view.borrow_mut().loaded = true;
                    capture(&view)?;
                }
                Ok::<_, windows::core::Error>(())
            })();
            // Certificate failures precede the certificate event; do not cancel
            // their deferrals by treating every IsSuccess=false as terminal.
            if result.is_err() {
                fail(&view);
            }
            Ok(())
        }));
        web.add_NavigationCompleted(&completed, &mut token)?;
        view.borrow_mut().tokens.push((1, token));

        let weak = Rc::downgrade(view);
        let received = WebResourceResponseReceivedEventHandler::create(Box::new(move |_, args| {
            let Some(view) = weak.upgrade() else {
                return Ok(());
            };
            let result = (|| {
                let args = args.ok_or_else(native_error)?;
                let uri = text(|p| args.Request()?.Uri(p))?;
                let v = view.borrow();
                if v.closed
                    || !https_origin(uri.as_str())
                        .is_ok_and(|origin| origin == v.request.expected_origin)
                    || v.uri.as_ref().is_none_or(|u| u.as_str() != uri.as_str())
                {
                    return Ok(());
                }
                drop(v);
                let pairs = headers(&args.Response()?)?;
                view.borrow_mut().headers = pairs;
                capture(&view)?;
                Ok::<_, windows::core::Error>(())
            })();
            if result.is_err() {
                fail(&view);
            }
            Ok(())
        }));
        web.cast::<ICoreWebView2_2>()?
            .add_WebResourceResponseReceived(&received, &mut token)?;
        view.borrow_mut().tokens.push((2, token));

        let weak = Rc::downgrade(view);
        let tls = ServerCertificateErrorDetectedEventHandler::create(Box::new(move |_, args| {
            let Some(args) = args else {
                return Ok(());
            };
            args.SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL)?;
            let Some(view) = weak.upgrade() else {
                return Ok(());
            };
            let result = (|| {
                let uri = text(|p| args.RequestUri(p))?;
                let origin = https_origin(uri.as_str()).map_err(|_| native_error())?;
                if view.borrow().closed {
                    return Ok(());
                }
                if !allowed(&mut view.borrow_mut(), uri.as_str(), false) {
                    return Err(native_error());
                }
                let chain = certificate_chain(&args)?;
                let mut v = view.borrow_mut();
                if v.pending.len() >= 16 {
                    return Err(native_error());
                }
                let challenge_id = Uuid::new_v4();
                let pending = Pending {
                    args: args.clone(),
                    deferral: args.GetDeferral()?,
                    generation: v.generation,
                    completed: false,
                };
                let transaction_id = v.request.transaction_id;
                v.pending.insert(challenge_id, pending);
                drop(v);
                emit(
                    &view,
                    BrowserClientMessage::Certificate {
                        challenge: BrowserCertificateChallenge {
                            transaction_id,
                            challenge_id,
                            origin,
                            chain,
                        },
                    },
                );
                Ok::<_, windows::core::Error>(())
            })();
            if result.is_err() {
                fail(&view);
            }
            Ok(())
        }));
        web.cast::<ICoreWebView2_14>()?
            .add_ServerCertificateErrorDetected(&tls, &mut token)?;
        view.borrow_mut().tokens.push((3, token));

        let weak = Rc::downgrade(view);
        let resource = WebResourceRequestedEventHandler::create(Box::new(move |_, args| {
            let Some(view) = weak.upgrade() else {
                return Ok(());
            };
            let result = (|| {
                let args = args.ok_or_else(native_error)?;
                let uri = text(|p| args.Request()?.Uri(p))?;
                let mut v = view.borrow_mut();
                if v.closed || !allowed(&mut v, uri.as_str(), false) {
                    let environment = v.web.cast::<ICoreWebView2_2>()?.Environment()?;
                    let denied = environment.CreateWebResourceResponse(
                        None::<&windows::Win32::System::Com::IStream>,
                        403,
                        &HSTRING::from("Forbidden"),
                        &HSTRING::from("Cache-Control: no-store\r\n"),
                    )?;
                    args.SetResponse(&denied)?;
                }
                Ok::<_, windows::core::Error>(())
            })();
            if result.is_err() {
                fail(&view);
            }
            Ok(())
        }));
        web.add_WebResourceRequested(&resource, &mut token)?;
        view.borrow_mut().tokens.push((4, token));
        web.cast::<ICoreWebView2_22>()?
            .AddWebResourceRequestedFilterWithRequestSourceKinds(
                &HSTRING::from("*"),
                COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
            )?;

        let popup = NewWindowRequestedEventHandler::create(Box::new(move |_, args| {
            if let Some(args) = args {
                args.SetHandled(true)?;
            }
            Ok(())
        }));
        web.add_NewWindowRequested(&popup, &mut token)?;
        view.borrow_mut().tokens.push((5, token));
        let weak = Rc::downgrade(view);
        let frame = NavigationStartingEventHandler::create(Box::new(move |_, args| {
            let Some(args) = args else {
                return Ok(());
            };
            let Some(view) = weak.upgrade() else {
                args.SetCancel(true)?;
                return Ok(());
            };
            let permitted = text(|p| args.Uri(p)).is_ok_and(|uri| {
                let mut v = view.borrow_mut();
                !v.closed && allowed(&mut v, uri.as_str(), false)
            });
            if !permitted {
                args.SetCancel(true)?;
            }
            Ok(())
        }));
        web.add_FrameNavigationStarting(&frame, &mut token)?;
        view.borrow_mut().tokens.push((6, token));
        let download = DownloadStartingEventHandler::create(Box::new(move |_, args| {
            if let Some(args) = args {
                args.SetCancel(true)?;
                args.SetHandled(true)?;
            }
            Ok(())
        }));
        web.cast::<ICoreWebView2_4>()?
            .add_DownloadStarting(&download, &mut token)?;
        view.borrow_mut().tokens.push((7, token));
        Ok(())
    }
}

pub(super) fn certificate_decision(
    window: &WebviewWindow,
    challenge_id: Uuid,
    accept: bool,
) -> Result<()> {
    let label = window.label().to_owned();
    window
        .run_on_main_thread(move || {
            let view = VIEWS.with(|views| views.borrow().get(&label).cloned());
            let Some(view) = view else {
                return;
            };
            let mut v = view.borrow_mut();
            let Some(mut pending) = v.pending.remove(&challenge_id) else {
                return;
            };
            if !accept || v.closed || pending.generation != v.generation {
                return;
            }
            drop(v);
            // The only allow operation follows a broker decision for this UUID and
            // copied native chain. The host/port resource guard limits cached scope.
            let result = unsafe {
                pending
                    .args
                    .SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW)
                    .and_then(|_| pending.deferral.Complete())
            };
            pending.completed = result.is_ok();
            drop(pending);
            if result.is_err() {
                fail(&view);
            }
        })
        .map_err(|_| adapter_error())
}

pub(super) fn close(window: &WebviewWindow) -> Result<()> {
    let label = window.label().to_owned();
    window
        .run_on_main_thread(move || {
            let view = VIEWS.with(|views| views.borrow_mut().remove(&label));
            let Some(view) = view else {
                return;
            };
            let mut v = view.borrow_mut();
            v.closed = true;
            v.pending.clear();
            v.headers.clear();
            v.uri = None;
            unsafe {
                let _ = v.web.Stop();
                for (kind, token) in v.tokens.drain(..).collect::<Vec<_>>() {
                    match kind {
                        0 => {
                            let _ = v.web.remove_NavigationStarting(token);
                        }
                        1 => {
                            let _ = v.web.remove_NavigationCompleted(token);
                        }
                        2 => {
                            if let Ok(web) = v.web.cast::<ICoreWebView2_2>() {
                                let _ = web.remove_WebResourceResponseReceived(token);
                            }
                        }
                        3 => {
                            if let Ok(web) = v.web.cast::<ICoreWebView2_14>() {
                                let _ = web.remove_ServerCertificateErrorDetected(token);
                            }
                        }
                        4 => {
                            let _ = v.web.remove_WebResourceRequested(token);
                        }
                        5 => {
                            let _ = v.web.remove_NewWindowRequested(token);
                        }
                        6 => {
                            let _ = v.web.remove_FrameNavigationStarting(token);
                        }
                        7 => {
                            if let Ok(web) = v.web.cast::<ICoreWebView2_4>() {
                                let _ = web.remove_DownloadStarting(token);
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                if let Ok(web) = v.web.cast::<ICoreWebView2_14>() {
                    let controller = v.controller.clone();
                    let callback = ClearServerCertificateErrorActionsCompletedHandler::create(
                        Box::new(move |_| {
                            let _ = controller.Close();
                            Ok(())
                        }),
                    );
                    if web.ClearServerCertificateErrorActions(&callback).is_err() {
                        let _ = v.controller.Close();
                    }
                } else {
                    let _ = v.controller.Close();
                }
            }
        })
        .map_err(|_| adapter_error())
}
