//! Native, main-thread-only WKWebView authentication boundary.
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    ffi::c_void,
    ptr::{self, NonNull},
    rc::Rc,
    sync::Arc,
};

use block2::{Block, RcBlock};
use objc2::{
    ClassType, DeclaredClass, MainThreadOnly, define_class, msg_send,
    rc::Retained,
    runtime::{AnyObject, NSObject, ProtocolObject},
    sel,
};
use objc2_foundation::{
    MainThreadMarker, NSArray, NSError, NSHTTPCookie, NSHTTPURLResponse, NSObjectProtocol,
    NSString, NSURLAuthenticationChallenge, NSURLAuthenticationMethodServerTrust, NSURLCredential,
    NSURLSessionAuthChallengeDisposition,
};
use objc2_web_kit::{
    WKContentWorld, WKNavigation, WKNavigationAction, WKNavigationActionPolicy,
    WKNavigationDelegate, WKNavigationResponse, WKNavigationResponsePolicy, WKWebView,
};
use ocvpn_model::{
    BrowserCertificateChallenge, BrowserClientMessage, BrowserPage, BrowserRequest, Error,
    ErrorCode, MAX_BROWSER_BYTES, NativeBrowserKind, Result, SecretText, https_origin,
};
use tauri::WebviewWindow;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;

// Foundation's objc2 bindings intentionally omit serverTrust/credentialForTrust.
// These Security/CoreFoundation C functions and the two Objective-C selectors
// use Apple's public ABI. The retained challenge owns its borrowed SecTrust.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTrustCopyCertificateChain(trust: *const c_void) -> *const c_void;
    fn SecCertificateCopyData(certificate: *const c_void) -> *const c_void;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFArrayGetCount(array: *const c_void) -> isize;
    fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;
    fn CFDataGetLength(data: *const c_void) -> isize;
    fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
    fn CFRelease(value: *const c_void);
}

type TrustHandler = RcBlock<dyn Fn(NSURLSessionAuthChallengeDisposition, *mut NSURLCredential)>;
struct PendingTrust {
    generation: u64,
    challenge: Retained<NSURLAuthenticationChallenge>,
    handler: TrustHandler,
}
impl PendingTrust {
    fn complete(self, accept: bool) {
        unsafe {
            let trust: *const c_void = msg_send![&*self.challenge.protectionSpace(), serverTrust];
            if accept && !trust.is_null() {
                let credential: Retained<NSURLCredential> =
                    msg_send![NSURLCredential::class(), credentialForTrust: trust];
                self.handler.call((
                    NSURLSessionAuthChallengeDisposition::UseCredential,
                    Retained::as_ptr(&credential).cast_mut(),
                ));
            } else {
                self.handler.call((
                    NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge,
                    ptr::null_mut(),
                ));
            }
        }
    }
}

struct State {
    request: Arc<BrowserRequest>,
    sender: Sender<BrowserClientMessage>,
    window: WebviewWindow,
    generation: Cell<u64>,
    closed: Cell<bool>,
    headers: RefCell<Option<(String, Vec<(SecretText, SecretText)>)>>,
    pending: RefCell<HashMap<Uuid, PendingTrust>>,
}
impl State {
    fn send(&self, message: BrowserClientMessage) {
        if self.closed.get() {
            return;
        }
        if self.sender.try_send(message).is_err() {
            self.cancel();
            super::defer_close(self.window.clone());
        }
    }
    fn fail(&self, message: &'static str) {
        self.send(BrowserClientMessage::Failed {
            transaction_id: self.request.transaction_id,
            error: Error::new(ErrorCode::UnsupportedAuthentication, message),
        });
        self.cancel();
        super::defer_close(self.window.clone());
    }
    fn cancel_pending(&self) {
        let pending = std::mem::take(&mut *self.pending.borrow_mut());
        for (_, callback) in pending {
            callback.complete(false);
        }
    }
    fn cancel(&self) {
        self.closed.set(true);
        self.generation.set(self.generation.get().wrapping_add(1));
        self.cancel_pending();
        self.headers.borrow_mut().take();
    }
    fn current(&self, webview: &WKWebView, generation: u64, uri: &str) -> bool {
        !self.closed.get()
            && self.generation.get() == generation
            && native_uri(webview).as_deref() == Some(uri)
            && https_origin(uri).is_ok_and(|origin| origin == self.request.expected_origin)
    }
    fn allowed(&self, uri: &str) -> bool {
        if https_origin(uri).is_ok() {
            return true;
        }
        if uri == self.request.uri.as_str() {
            return true;
        }
        if uri == "about:blank" && self.generation.get() == 0 {
            return true;
        }
        self.request.kind == NativeBrowserKind::External
            && url::Url::parse(uri).is_ok_and(|url| {
                url.scheme() == "http"
                    && url.host_str() == Some("[::1]")
                    && url.port() == Some(29786)
                    && url.username().is_empty()
                    && url.password().is_none()
            })
    }
}

pub struct DelegateIvars {
    state: Rc<State>,
    original: Option<Retained<ProtocolObject<dyn WKNavigationDelegate>>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[ivars = DelegateIvars]
    pub struct AuthenticationDelegate;

    unsafe impl NSObjectProtocol for AuthenticationDelegate {}
    unsafe impl WKNavigationDelegate for AuthenticationDelegate {
        #[unsafe(method(webView:decidePolicyForNavigationAction:decisionHandler:))]
        fn policy(
            &self,
            webview: &WKWebView,
            action: &WKNavigationAction,
            handler: &Block<dyn Fn(WKNavigationActionPolicy)>,
        ) {
            unsafe {
                let state = &self.ivars().state;
                let uri = action
                    .request()
                    .URL()
                    .and_then(|url| url.absoluteString())
                    .map(|s| s.to_string());
                if state.closed.get()
                    || !uri.as_deref().is_some_and(|uri| state.allowed(uri))
                    || action.targetFrame().is_none()
                    || action.shouldPerformDownload()
                {
                    handler.call((WKNavigationActionPolicy::Cancel,));
                    return;
                }
                if action
                    .targetFrame()
                    .is_some_and(|frame| frame.isMainFrame())
                {
                    state.generation.set(state.generation.get().wrapping_add(1));
                    state.cancel_pending();
                    state.headers.borrow_mut().take();
                }
                if let Some(original) = &self.ivars().original {
                    if original.respondsToSelector(
                        sel!(webView:decidePolicyForNavigationAction:decisionHandler:),
                    ) {
                        let _: () = msg_send![original, webView: webview, decidePolicyForNavigationAction: action, decisionHandler: handler];
                        return;
                    }
                }
                handler.call((WKNavigationActionPolicy::Allow,));
            }
        }

        #[unsafe(method(webView:decidePolicyForNavigationResponse:decisionHandler:))]
        fn response(
            &self,
            webview: &WKWebView,
            response: &WKNavigationResponse,
            handler: &Block<dyn Fn(WKNavigationResponsePolicy)>,
        ) {
            unsafe {
                let state = &self.ivars().state;
                let native = response.response();
                let uri = native
                    .URL()
                    .and_then(|url| url.absoluteString())
                    .map(|s| s.to_string());
                if state.closed.get()
                    || !response.canShowMIMEType()
                    || !uri.as_deref().is_some_and(|uri| state.allowed(uri))
                {
                    handler.call((WKNavigationResponsePolicy::Cancel,));
                    return;
                }
                if response.isForMainFrame() {
                    if let Some(uri) = uri.filter(|uri| {
                        https_origin(uri)
                            .is_ok_and(|origin| origin == state.request.expected_origin)
                    }) {
                        if let Some(http) = native.downcast_ref::<NSHTTPURLResponse>() {
                            match response_headers(http) {
                                Ok(headers) => *state.headers.borrow_mut() = Some((uri, headers)),
                                Err(_) => {
                                    handler.call((WKNavigationResponsePolicy::Cancel,));
                                    state.fail("Browser response headers exceeded the authentication limit");
                                    return;
                                }
                            }
                        }
                    }
                }
                if let Some(original) = &self.ivars().original {
                    if original.respondsToSelector(
                        sel!(webView:decidePolicyForNavigationResponse:decisionHandler:),
                    ) {
                        let _: () = msg_send![original, webView: webview, decidePolicyForNavigationResponse: response, decisionHandler: handler];
                        return;
                    }
                }
                handler.call((WKNavigationResponsePolicy::Allow,));
            }
        }

        #[unsafe(method(webView:didCommitNavigation:))]
        fn commit(&self, webview: &WKWebView, navigation: Option<&WKNavigation>) {
            unsafe {
                if let Some(original) = &self.ivars().original {
                    if original.respondsToSelector(sel!(webView:didCommitNavigation:)) {
                        let _: () =
                            msg_send![original, webView: webview, didCommitNavigation: navigation];
                    }
                }
            }
        }

        #[unsafe(method(webView:didFinishNavigation:))]
        fn finish(&self, webview: &WKWebView, navigation: Option<&WKNavigation>) {
            unsafe {
                if let Some(original) = &self.ivars().original {
                    if original.respondsToSelector(sel!(webView:didFinishNavigation:)) {
                        let _: () =
                            msg_send![original, webView: webview, didFinishNavigation: navigation];
                    }
                }
            }
            let state = &self.ivars().state;
            if let Some(uri) = native_uri(webview) {
                let generation = state.generation.get();
                if state.current(webview, generation, &uri) {
                    let retained = unsafe { Retained::retain(ptr::from_ref(webview).cast_mut()) };
                    if let Some(webview) = retained {
                        capture(state.clone(), webview, generation, uri, false);
                    }
                }
            }
        }

        #[unsafe(method(webView:didReceiveAuthenticationChallenge:completionHandler:))]
        fn challenge(
            &self,
            _webview: &WKWebView,
            challenge: &NSURLAuthenticationChallenge,
            handler: &Block<dyn Fn(NSURLSessionAuthChallengeDisposition, *mut NSURLCredential)>,
        ) {
            unsafe {
                let state = &self.ivars().state;
                let space = challenge.protectionSpace();
                if state.closed.get() {
                    handler.call((
                        NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge,
                        ptr::null_mut(),
                    ));
                    return;
                }
                if &*space.authenticationMethod() != NSURLAuthenticationMethodServerTrust {
                    handler.call((
                        NSURLSessionAuthChallengeDisposition::PerformDefaultHandling,
                        ptr::null_mut(),
                    ));
                    return;
                }
                let host = space.host().to_string();
                let authority = if host.contains(':') && !host.starts_with('[') {
                    format!("[{host}]")
                } else {
                    host
                };
                let port = space.port();
                let origin = if !space.isProxy()
                    && (0..=65535).contains(&port)
                    && space
                        .protocol()
                        .is_some_and(|protocol| protocol.to_string().eq_ignore_ascii_case("https"))
                {
                    https_origin(&format!(
                        "https://{authority}:{}",
                        if port == 0 { 443 } else { port }
                    ))
                    .ok()
                } else {
                    None
                };
                let trust: *const c_void = msg_send![&*space, serverTrust];
                let chain = copy_chain(trust);
                let (Some(origin), Ok(chain)) = (origin, chain) else {
                    handler.call((
                        NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge,
                        ptr::null_mut(),
                    ));
                    state.fail("WKWebView could not supply a scoped server certificate chain");
                    return;
                };
                if state.pending.borrow().len() >= 16 {
                    handler.call((
                        NSURLSessionAuthChallengeDisposition::CancelAuthenticationChallenge,
                        ptr::null_mut(),
                    ));
                    state.fail("Too many simultaneous browser certificate challenges");
                    return;
                }
                let challenge_id = Uuid::new_v4();
                state.pending.borrow_mut().insert(
                    challenge_id,
                    PendingTrust {
                        generation: state.generation.get(),
                        challenge: Retained::retain(ptr::from_ref(challenge).cast_mut())
                            .expect("A borrowed Objective-C object is nonnull"),
                        handler: handler.copy(),
                    },
                );
                state.send(BrowserClientMessage::Certificate {
                    challenge: BrowserCertificateChallenge {
                        transaction_id: state.request.transaction_id,
                        challenge_id,
                        origin,
                        chain,
                    },
                });
            }
        }

        #[unsafe(method(webViewWebContentProcessDidTerminate:))]
        fn terminated(&self, _webview: &WKWebView) {
            self.ivars()
                .state
                .fail("The authentication web content process terminated");
        }
    }
);

struct Attached {
    webview: Retained<WKWebView>,
    delegate: Retained<AuthenticationDelegate>,
}
thread_local! {
    // WKWebView.navigationDelegate is weak. All retained Objective-C objects,
    // copied blocks and Rc state live and are destroyed on this GUI thread.
    static ATTACHED: RefCell<HashMap<String, Attached>> = RefCell::new(HashMap::new());
}

pub(super) fn attach(
    window: &WebviewWindow,
    request: Arc<BrowserRequest>,
    sender: Sender<BrowserClientMessage>,
) -> Result<()> {
    request.validate()?;
    // WKWebView doesn't document that authentication challenges observe every
    // trusted/cached connection. Do not promise strict saved pins on that hook.
    if !request.tls.pins.is_empty() {
        return Err(Error::new(
            ErrorCode::UnsupportedAuthentication,
            "WKWebView cannot guarantee pre-request enforcement of saved certificate pins; use manual or system browser authentication with its own trust policy",
        ));
    }
    let owned_window = window.clone();
    window
        .with_webview(move |native| {
            let Some(mtm) = MainThreadMarker::new() else {
                let _ = sender.try_send(BrowserClientMessage::Failed {
                    transaction_id: request.transaction_id,
                    error: Error::new(
                        ErrorCode::RuntimeFailure,
                        "WKWebView attachment was not dispatched to the main thread",
                    ),
                });
                super::defer_close(owned_window.clone());
                return;
            };
            let Some(webview) = (unsafe { Retained::retain(native.inner() as *mut WKWebView) })
            else {
                let _ = sender.try_send(BrowserClientMessage::Failed {
                    transaction_id: request.transaction_id,
                    error: Error::new(
                        ErrorCode::RuntimeFailure,
                        "Tauri did not supply a WKWebView",
                    ),
                });
                super::defer_close(owned_window.clone());
                return;
            };
            let state = Rc::new(State {
                request,
                sender,
                window: owned_window,
                generation: Cell::new(0),
                closed: Cell::new(false),
                headers: RefCell::new(None),
                pending: RefCell::new(HashMap::new()),
            });
            unsafe {
                if webview.configuration().websiteDataStore().isPersistent()
                    || native_uri(&webview)
                        .as_deref()
                        .is_some_and(|uri| uri != "about:blank")
                {
                    state.fail("Authentication requires an unused nonpersistent WKWebView");
                    return;
                }
                let content = webview.configuration().userContentController();
                content.removeAllUserScripts();
                content.removeScriptMessageHandlerForName(&NSString::from_str("ipc"));
                let original = webview.navigationDelegate();
                let delegate = mtm
                    .alloc::<AuthenticationDelegate>()
                    .set_ivars(DelegateIvars {
                        state: state.clone(),
                        original,
                    });
                let delegate: Retained<AuthenticationDelegate> = msg_send![super(delegate), init];
                ATTACHED.with(|attached| {
                    let mut attached = attached.borrow_mut();
                    if attached.contains_key(state.window.label()) {
                        state.fail("Authentication window already has a native delegate");
                        return;
                    }
                    webview.setNavigationDelegate(Some(ProtocolObject::from_ref(&*delegate)));
                    attached.insert(
                        state.window.label().to_owned(),
                        Attached { webview, delegate },
                    );
                });
                if !state.closed.get() && super::attached(&state.request, &state.sender).is_err() {
                    state.fail("Could not start the attached native authentication window");
                }
            }
        })
        .map_err(|_| {
            Error::new(
                ErrorCode::RuntimeFailure,
                "Could not attach the WKWebView authentication delegate",
            )
        })
}

pub(super) fn certificate_decision(
    window: &WebviewWindow,
    challenge_id: Uuid,
    accept: bool,
) -> Result<()> {
    let label = window.label().to_owned();
    window
        .run_on_main_thread(move || {
            let state = ATTACHED.with(|attached| {
                attached
                    .borrow()
                    .get(&label)
                    .map(|entry| entry.delegate.ivars().state.clone())
            });
            if let Some(state) = state {
                let pending = state.pending.borrow_mut().remove(&challenge_id);
                if let Some(pending) = pending {
                    let accept = accept
                        && !state.closed.get()
                        && state.generation.get() == pending.generation;
                    pending.complete(accept);
                }
            }
        })
        .map_err(|_| {
            Error::new(
                ErrorCode::RuntimeFailure,
                "Could not dispatch the browser certificate decision",
            )
        })
}

pub(super) fn close(window: &WebviewWindow) -> Result<()> {
    let label = window.label().to_owned();
    window
        .run_on_main_thread(move || {
            let attached = ATTACHED.with(|entries| entries.borrow_mut().remove(&label));
            if let Some(attached) = attached {
                attached.delegate.ivars().state.cancel();
                unsafe {
                    attached.webview.stopLoading();
                    attached
                        .webview
                        .setNavigationDelegate(attached.delegate.ivars().original.as_deref());
                }
            }
        })
        .map_err(|_| {
            Error::new(
                ErrorCode::RuntimeFailure,
                "Could not release the WKWebView authentication delegate",
            )
        })
}

fn native_uri(webview: &WKWebView) -> Option<String> {
    unsafe {
        webview
            .URL()
            .and_then(|url| url.absoluteString())
            .map(|uri| uri.to_string())
    }
}

fn copy_chain(trust: *const c_void) -> Result<Vec<Vec<u8>>> {
    if trust.is_null() {
        return Err(Error::invalid("Missing browser server trust"));
    }
    unsafe {
        struct OwnedArray(*const c_void);
        impl Drop for OwnedArray {
            fn drop(&mut self) {
                unsafe {
                    CFRelease(self.0);
                }
            }
        }
        let array = SecTrustCopyCertificateChain(trust);
        if array.is_null() {
            return Err(Error::invalid("Missing browser certificate chain"));
        }
        let array = OwnedArray(array);
        let count = CFArrayGetCount(array.0);
        if !(1..=32).contains(&count) {
            return Err(Error::invalid("Invalid browser chain length"));
        }
        let mut chain = Vec::with_capacity(count as usize);
        let mut total = 0usize;
        for index in 0..count {
            let cert = CFArrayGetValueAtIndex(array.0, index);
            if cert.is_null() {
                return Err(Error::invalid("Missing browser certificate"));
            }
            let data = SecCertificateCopyData(cert);
            if data.is_null() {
                return Err(Error::invalid("Missing browser certificate DER"));
            }
            let length = CFDataGetLength(data);
            let bytes = CFDataGetBytePtr(data);
            let valid =
                length > 0 && length as usize <= MAX_BROWSER_BYTES - total && !bytes.is_null();
            if valid {
                total += length as usize;
                chain.push(std::slice::from_raw_parts(bytes, length as usize).to_vec());
            }
            CFRelease(data);
            if !valid {
                return Err(Error::invalid("Invalid browser certificate DER"));
            }
        }
        Ok(chain)
    }
}

fn response_headers(response: &NSHTTPURLResponse) -> Result<Vec<(SecretText, SecretText)>> {
    let dictionary = response.allHeaderFields();
    if dictionary.count() > 128 {
        return Err(Error::invalid("Too many response headers"));
    }
    let mut headers = Vec::with_capacity(dictionary.count());
    let mut bytes = 0usize;
    for key in dictionary.allKeys().iter() {
        let Some(name) = key.downcast_ref::<NSString>() else {
            return Err(Error::invalid("Invalid response header name"));
        };
        let value = dictionary
            .objectForKey(&key)
            .ok_or_else(|| Error::invalid("Missing response header value"))?;
        let Some(value) = value.downcast_ref::<NSString>() else {
            return Err(Error::invalid("Invalid response header value"));
        };
        if name.len() > MAX_BROWSER_BYTES || value.len() > MAX_BROWSER_BYTES {
            return Err(Error::invalid("Oversized response header"));
        }
        let (name, value) = (name.to_string(), value.to_string());
        bytes += name.len() + value.len();
        if bytes > MAX_BROWSER_BYTES {
            return Err(Error::invalid("Oversized response headers"));
        }
        headers.push((SecretText::new(name), SecretText::new(value)));
    }
    Ok(headers)
}

// Isolated-world DOM access: page JS cannot replace XMLSerializer, timers or
// location accessors. Serialize the entire Document, including comments outside
// documentElement (GP's completion can consist solely of an XML comment).
const DOCUMENT: &str = "(() => { let d=''; for(const n of document.childNodes){if(n.nodeType===10)continue;d+=new XMLSerializer().serializeToString(n);if(d.length>1048576)throw new Error('document limit');} return JSON.stringify([location.href,d]); })()";
const POLL_DOCUMENT: &str = "await new Promise(resolve => setTimeout(resolve, 500)); let d=''; for(const n of document.childNodes){if(n.nodeType===10)continue;d+=new XMLSerializer().serializeToString(n);if(d.length>1048576)throw new Error('document limit');} return JSON.stringify([location.href,d]);";

fn capture(
    state: Rc<State>,
    webview: Retained<WKWebView>,
    generation: u64,
    uri: String,
    delayed: bool,
) {
    if !state.current(&webview, generation, &uri) {
        return;
    }
    let callback_state = state.clone();
    let callback_view = webview.clone();
    let callback = RcBlock::new(move |value: *mut AnyObject, error: *mut NSError| {
        if !callback_state.current(&callback_view, generation, &uri) {
            return;
        }
        let value = unsafe { value.as_ref() }.and_then(|value| value.downcast_ref::<NSString>());
        let Some(value) = value.filter(|_| error.is_null()) else {
            callback_state.fail("WKWebView could not capture the authentication document");
            return;
        };
        if value.len() > MAX_BROWSER_BYTES * 2 {
            callback_state.fail("Browser authentication document exceeded its limit");
            return;
        }
        let Ok([document_uri, document]) = serde_json::from_str::<[String; 2]>(&value.to_string())
        else {
            callback_state.fail("WKWebView returned an invalid authentication document");
            return;
        };
        if document_uri != uri || document.len() > MAX_BROWSER_BYTES {
            callback_state
                .fail("Browser authentication document changed origin or exceeded its limit");
            return;
        }
        // Cookies may change without a DOM mutation. Keep one bounded capture
        // in flight, and let the native protocol detector decide completion.
        capture_cookies(
            callback_state.clone(),
            callback_view.clone(),
            generation,
            uri.clone(),
            document,
        );
    });
    unsafe {
        let world = WKContentWorld::defaultClientWorld(webview.mtm());
        if delayed {
            webview.callAsyncJavaScript_arguments_inFrame_inContentWorld_completionHandler(
                &NSString::from_str(POLL_DOCUMENT),
                None,
                None,
                &world,
                Some(&callback),
            );
        } else {
            webview.evaluateJavaScript_inFrame_inContentWorld_completionHandler(
                &NSString::from_str(DOCUMENT),
                None,
                &world,
                Some(&callback),
            );
        }
    }
}

fn capture_cookies(
    state: Rc<State>,
    webview: Retained<WKWebView>,
    generation: u64,
    uri: String,
    document: String,
) {
    let Ok(url) = url::Url::parse(&uri) else {
        return;
    };
    let Some(host) = url.host_str().map(str::to_owned) else {
        return;
    };
    let callback_view = webview.clone();
    let callback = RcBlock::new(move |cookies: NonNull<NSArray<NSHTTPCookie>>| {
        if !state.current(&callback_view, generation, &uri) {
            return;
        }
        let mut selected = Vec::new();
        let mut bytes = document.len() + uri.len();
        for cookie in unsafe { cookies.as_ref() }.iter() {
            let domain = cookie.domain().to_string().to_ascii_lowercase();
            let matches = if let Some(domain) = domain.strip_prefix('.') {
                host == domain
                    || host
                        .strip_suffix(domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            } else {
                host == domain
            };
            let path = cookie.path().to_string();
            let path_matches = url.path() == path
                || url
                    .path()
                    .strip_prefix(&path)
                    .is_some_and(|suffix| path.ends_with('/') || suffix.starts_with('/'));
            if !matches
                || !path_matches
                || cookie
                    .expiresDate()
                    .is_some_and(|date| date.timeIntervalSinceNow() <= 0.0)
            {
                continue;
            }
            let name = cookie.name();
            let value = cookie.value();
            if selected.len() >= 128
                || name.len() > MAX_BROWSER_BYTES
                || value.len() > MAX_BROWSER_BYTES
            {
                state.fail("Browser authentication cookies exceeded their limit");
                return;
            }
            let (name, value) = (name.to_string(), value.to_string());
            bytes += name.len() + value.len();
            if bytes > MAX_BROWSER_BYTES {
                state.fail("Browser authentication cookies exceeded their limit");
                return;
            }
            selected.push((SecretText::new(name), SecretText::new(value)));
        }
        let headers = state
            .headers
            .borrow()
            .as_ref()
            .filter(|(header_uri, _)| header_uri == &uri)
            .map(|(_, headers)| {
                headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            SecretText::new(name.as_str().to_owned()),
                            SecretText::new(value.as_str().to_owned()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let page = BrowserPage {
            uri: SecretText::new(uri.clone()),
            cookies: selected,
            headers,
            document: Some(SecretText::new(document.clone())),
        };
        if page.validate(&state.request.expected_origin).is_err() {
            state.fail("Browser authentication response exceeded its limit");
            return;
        }
        state.send(BrowserClientMessage::Page {
            transaction_id: state.request.transaction_id,
            page,
        });
        capture(
            state.clone(),
            callback_view.clone(),
            generation,
            uri.clone(),
            true,
        );
    });
    unsafe {
        webview
            .configuration()
            .websiteDataStore()
            .httpCookieStore()
            .getAllCookies(&callback);
    }
}
