// SPDX-License-Identifier: GPL-3.0-only
//! WebKitGTK exposes trusted TLS certificates only after receiving a response
//! (get_tls_info / LOAD_COMMITTED), not as a pre-request verifier. Saved strict
//! pins therefore cannot safely be implemented with its error-only TLS signal.
use gio::prelude::*;
use ocvpn_model::{
    BrowserCertificateChallenge, BrowserClientMessage, BrowserPage, BrowserRequest, Error,
    MAX_BROWSER_BYTES, NativeBrowserKind, Result, SecretText, https_origin,
};
use std::{
    cell::RefCell,
    collections::HashMap,
    rc::{Rc, Weak},
    sync::Arc,
};
use tauri::WebviewWindow;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;
use webkit2gtk::{
    CookieManagerExt, LoadEvent, NavigationPolicyDecision, NavigationPolicyDecisionExt,
    PolicyDecisionExt, PolicyDecisionType, TLSErrorsPolicy, URIRequestExt, URIResponseExt,
    UserContentManagerExt, WebContextExt, WebResourceExt, WebView, WebViewExt,
    WebsiteDataManagerExt, gio, glib,
};

use javascriptcore::ValueExt;
type Pair = (SecretText, SecretText);
struct Challenge {
    id: Uuid,
    generation: u64,
    uri: SecretText,
    host: String,
    certificate: gio::TlsCertificate,
}
struct State {
    window: WebviewWindow,
    view: glib::WeakRef<WebView>,
    request: Arc<BrowserRequest>,
    sender: Sender<BrowserClientMessage>,
    generation: u64,
    closed: bool,
    loaded: bool,
    capturing: bool,
    timer: Option<glib::SourceId>,
    pending: Option<Challenge>,
    cancel: gio::Cancellable,
    signals: Vec<(glib::WeakRef<glib::Object>, glib::SignalHandlerId)>,
    resource_signal: Option<(glib::WeakRef<glib::Object>, glib::SignalHandlerId)>,
}
thread_local! {
    static WINDOWS: RefCell<HashMap<String, Rc<RefCell<State>>>> = RefCell::new(HashMap::new());
}
fn disconnect(signal: (glib::WeakRef<glib::Object>, glib::SignalHandlerId)) {
    if let Some(object) = signal.0.upgrade() {
        object.disconnect(signal.1);
    }
}
fn fail(state: &Rc<RefCell<State>>, message: &'static str) {
    let window = {
        let mut s = state.borrow_mut();
        if s.closed {
            return;
        }
        s.closed = true;
        s.cancel.cancel();
        s.pending = None;
        if let Some(timer) = s.timer.take() {
            timer.remove();
        }
        let _ = s.sender.try_send(BrowserClientMessage::Failed {
            transaction_id: s.request.transaction_id,
            error: Error::invalid(message),
        });
        s.window.clone()
    };
    WINDOWS.with(|windows| {
        windows.borrow_mut().remove(window.label());
    });
    {
        let mut s = state.borrow_mut();
        for signal in s.signals.drain(..) {
            disconnect(signal);
        }
        if let Some(signal) = s.resource_signal.take() {
            disconnect(signal);
        }
    }
    let view = state.borrow().view.upgrade();
    if let Some(view) = view {
        view.stop_loading();
    }
    super::defer_close(window);
}
fn send(state: &Rc<RefCell<State>>, message: BrowserClientMessage) {
    let failed = state.borrow().sender.try_send(message).is_err();
    if failed {
        fail(state, "Browser authentication event channel is unavailable");
    }
}
fn current(state: &Rc<RefCell<State>>, generation: u64, uri: &str) -> Option<WebView> {
    let s = state.borrow();
    if s.closed
        || s.generation != generation
        || s.pending.is_some()
        || https_origin(uri).ok().as_ref() != Some(&s.request.expected_origin)
    {
        return None;
    }
    let view = s.view.upgrade()?;
    (view.uri().as_deref() == Some(uri)).then_some(view)
}
fn allowed(request: &BrowserRequest, uri: &str) -> bool {
    if uri == "about:blank" || uri == request.uri.as_str() || https_origin(uri).is_ok() {
        return true;
    }
    request.kind == NativeBrowserKind::External
        && tauri::Url::parse(uri).ok().is_some_and(|u| {
            u.scheme() == "http"
                && u.host_str() == Some("[::1]")
                && u.port() == Some(29786)
                && u.username().is_empty()
                && u.password().is_none()
        })
}
fn headers(view: &WebView, uri: &str) -> Option<Vec<Pair>> {
    let resource = view.main_resource()?;
    let response = resource.response()?;
    if response.uri().as_deref() != Some(uri) {
        return None;
    }
    let mut pairs = Vec::new();
    let mut bytes = 0usize;
    let mut overflow = false;
    if let Some(headers) = response.http_headers() {
        headers.foreach(|name, value| {
            bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
            if bytes > MAX_BROWSER_BYTES || pairs.len() >= 128 {
                overflow = true;
                return;
            }
            pairs.push((
                SecretText::new(name.to_owned()),
                SecretText::new(value.to_owned()),
            ));
        });
    }
    (!overflow).then_some(pairs)
}
fn capture(state: &Rc<RefCell<State>>, with_document: bool) {
    let (generation, uri, cancel) = {
        let s = state.borrow();
        if s.closed || s.capturing || (with_document && !s.loaded) {
            return;
        }
        let Some(view) = s.view.upgrade() else {
            return;
        };
        let Some(uri) = view.uri() else {
            return;
        };
        (s.generation, uri.to_string(), s.cancel.clone())
    };
    let Some(view) = current(state, generation, &uri) else {
        return;
    };
    let Some(headers) = headers(&view, &uri) else {
        if with_document {
            fail(
                state,
                "Browser response headers are unavailable or exceed the limit",
            );
        }
        return;
    };
    state.borrow_mut().capturing = true;
    if !with_document {
        capture_cookies(state, generation, uri, headers, None);
        return;
    }
    let weak = Rc::downgrade(state);
    // Fixed isolated-world extraction runs after page JavaScript/load completion.
    // Include top-level comments as well as comments inside the document element.
    view.evaluate_javascript(
        "(()=>{let s='';for(const n of document.childNodes){if(n.nodeType===10)continue;s+=new XMLSerializer().serializeToString(n);if(s.length>1048576)throw new Error('limit');}return s;})()",
        Some("ocvpn-auth-capture"), None, Some(&cancel), move |result| {
            let Some(state) = weak.upgrade() else { return; };
            if current(&state, generation, &uri).is_none() {
                if state.borrow().generation == generation { state.borrow_mut().capturing = false; }
                return;
            }
            match result {
                Ok(value) if value.is_string() => {
                    let document = value.to_str();
                    if document.len() > MAX_BROWSER_BYTES {
                        fail(&state, "Browser completion document exceeds the limit"); return;
                    }
                    capture_cookies(&state, generation, uri, headers, Some(SecretText::new(document.to_string())));
                }
                _ => fail(&state, "Browser completion document could not be captured"),
            }
        });
}
fn capture_cookies(
    state: &Rc<RefCell<State>>,
    generation: u64,
    uri: String,
    headers: Vec<Pair>,
    document: Option<SecretText>,
) {
    let Some(view) = current(state, generation, &uri) else {
        return;
    };
    let Some(manager) = view.website_data_manager().and_then(|m| m.cookie_manager()) else {
        fail(state, "Browser cookie manager is unavailable");
        return;
    };
    let weak = Rc::downgrade(state);
    let cancel = state.borrow().cancel.clone();
    let query = uri.clone();
    manager.cookies(&query, Some(&cancel), move |result| {
        let Some(state) = weak.upgrade() else {
            return;
        };
        if state.borrow().generation == generation {
            state.borrow_mut().capturing = false;
        }
        if current(&state, generation, &uri).is_none() {
            return;
        }
        let Ok(cookies) = result else {
            fail(&state, "Browser completion cookies could not be captured");
            return;
        };
        if cookies.len() > 128 {
            fail(&state, "Browser completion cookies exceed the limit");
            return;
        }
        let mut pairs = Vec::with_capacity(cookies.len());
        let mut bytes = 0usize;
        for mut cookie in cookies {
            let (Some(name), Some(value)) = (cookie.name(), cookie.value()) else {
                continue;
            };
            bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
            if bytes > MAX_BROWSER_BYTES {
                fail(&state, "Browser completion cookies exceed the limit");
                return;
            }
            pairs.push((
                SecretText::new(name.to_string()),
                SecretText::new(value.to_string()),
            ));
        }
        let page = BrowserPage {
            uri: SecretText::new(uri),
            cookies: pairs,
            headers,
            document,
        };
        let (valid, transaction_id) = {
            let s = state.borrow();
            (
                page.validate(&s.request.expected_origin).is_ok(),
                s.request.transaction_id,
            )
        };
        if !valid {
            fail(&state, "Invalid browser completion response");
            return;
        }
        send(
            &state,
            BrowserClientMessage::Page {
                transaction_id,
                page,
            },
        );
    });
}
fn retain(state: &Rc<RefCell<State>>, view: &WebView, id: glib::SignalHandlerId) {
    state
        .borrow_mut()
        .signals
        .push((view.clone().upcast::<glib::Object>().downgrade(), id));
}
pub(super) fn attach(
    window: &WebviewWindow,
    request: Arc<BrowserRequest>,
    sender: Sender<BrowserClientMessage>,
) -> Result<()> {
    if !request.tls.pins.is_empty() {
        return Err(Error::invalid(
            "WebKitGTK cannot enforce strict saved pins before sending credentials; use native/manual authentication",
        ));
    }
    let owned_window = window.clone();
    window
        .with_webview(move |native| {
            let view = native.inner();
            let state = Rc::new(RefCell::new(State {
                window: owned_window.clone(),
                view: view.downgrade(),
                request,
                sender,
                generation: 0,
                closed: false,
                pending: None,
                cancel: gio::Cancellable::new(),
                loaded: false,
                capturing: false,
                timer: None,
                signals: Vec::new(),
                resource_signal: None,
            }));
            if view
                .uri()
                .as_deref()
                .is_some_and(|uri| uri != "about:blank")
                || !view
                    .website_data_manager()
                    .is_some_and(|m| m.is_ephemeral())
            {
                fail(
                    &state,
                    "Authentication requires an initially blank, ephemeral WebKit profile",
                );
                return;
            }
            let Some(manager) = view.website_data_manager() else {
                fail(&state, "Browser data manager is unavailable");
                return;
            };
            manager.set_tls_errors_policy(TLSErrorsPolicy::Fail);
            if let Some(manager) = view.user_content_manager() {
                manager.unregister_script_message_handler("ipc");
                manager.remove_all_scripts();
            }
            WINDOWS.with(|windows| {
                windows
                    .borrow_mut()
                    .insert(owned_window.label().to_owned(), state.clone());
            });
            let weak = Rc::downgrade(&state);
            state.borrow_mut().timer = Some(glib::timeout_add_local(
                std::time::Duration::from_millis(500),
                move || {
                    let Some(state) = weak.upgrade() else {
                        return glib::ControlFlow::Break;
                    };
                    capture(&state, true);
                    glib::ControlFlow::Continue
                },
            ));
            let weak = Rc::downgrade(&state);
            retain(
                &state,
                &view,
                view.connect_decide_policy(move |_, decision, kind| {
                    let Some(state) = weak.upgrade() else {
                        decision.ignore();
                        return true;
                    };
                    if kind == PolicyDecisionType::NewWindowAction {
                        decision.ignore();
                        return true;
                    }
                    if let Some(navigation) = decision.downcast_ref::<NavigationPolicyDecision>() {
                        let uri = navigation
                            .navigation_action()
                            .and_then(|a| a.request())
                            .and_then(|r| r.uri());
                        if state.borrow().closed
                            || uri
                                .as_ref()
                                .is_none_or(|uri| !allowed(&state.borrow().request, uri))
                        {
                            decision.ignore();
                            return true;
                        }
                    }
                    false
                }),
            );
            let weak = Rc::downgrade(&state);
            retain(
                &state,
                &view,
                view.connect_load_changed(move |_, event| {
                    let Some(state) = weak.upgrade() else {
                        return;
                    };
                    if event == LoadEvent::Started {
                        let mut s = state.borrow_mut();
                        s.generation = s.generation.wrapping_add(1);
                        s.loaded = false;
                        s.capturing = false;
                        s.cancel.cancel();
                        s.cancel = gio::Cancellable::new();
                        s.pending = None;
                        if let Some(signal) = s.resource_signal.take() {
                            disconnect(signal);
                        }
                    } else if event == LoadEvent::Finished && state.borrow().pending.is_none() {
                        state.borrow_mut().loaded = true;
                        capture(&state, true);
                    }
                }),
            );
            let weak = Rc::downgrade(&state);
            retain(
                &state,
                &view,
                view.connect_resource_load_started(move |view, resource, _| {
                    let Some(state) = weak.upgrade() else {
                        return;
                    };
                    if view.main_resource().as_ref() != Some(resource) {
                        return;
                    }
                    if let Some(signal) = state.borrow_mut().resource_signal.take() {
                        disconnect(signal);
                    }
                    let weak: Weak<RefCell<State>> = Rc::downgrade(&state);
                    let generation = state.borrow().generation;
                    let id = resource.connect_response_notify(move |_| {
                        let Some(state) = weak.upgrade() else {
                            return;
                        };
                        if state.borrow().generation == generation {
                            capture(&state, false);
                        }
                    });
                    state.borrow_mut().resource_signal =
                        Some((resource.clone().upcast::<glib::Object>().downgrade(), id));
                }),
            );
            let weak = Rc::downgrade(&state);
            retain(
                &state,
                &view,
                view.connect_load_failed_with_tls_errors(move |_, uri, certificate, _| {
                    let Some(state) = weak.upgrade() else {
                        return true;
                    };
                    let Ok(origin) = https_origin(uri) else {
                        fail(&state, "Invalid browser TLS origin");
                        return true;
                    };
                    let mut chain = Vec::new();
                    let mut cursor = Some(certificate.clone());
                    let mut bytes = 0usize;
                    while let Some(cert) = cursor {
                        let Some(der) = cert.certificate() else {
                            fail(&state, "Browser TLS certificate DER is unavailable");
                            return true;
                        };
                        bytes = bytes.saturating_add(der.len());
                        if chain.len() >= 16 || bytes > MAX_BROWSER_BYTES / 4 {
                            fail(&state, "Browser TLS certificate chain exceeds the limit");
                            return true;
                        }
                        chain.push(der.to_vec());
                        cursor = cert.issuer();
                    }
                    let challenge_id = Uuid::new_v4();
                    let transaction_id = {
                        let mut s = state.borrow_mut();
                        if s.closed || s.pending.is_some() {
                            drop(s);
                            fail(&state, "Overlapping browser TLS challenges");
                            return true;
                        }
                        s.cancel.cancel();
                        s.cancel = gio::Cancellable::new();
                        s.pending = Some(Challenge {
                            id: challenge_id,
                            generation: s.generation,
                            uri: SecretText::new(uri.to_owned()),
                            host: origin
                                .host_str()
                                .unwrap_or_default()
                                .trim_matches(['[', ']'])
                                .to_owned(),
                            certificate: certificate.clone(),
                        });
                        s.request.transaction_id
                    };
                    send(
                        &state,
                        BrowserClientMessage::Certificate {
                            challenge: BrowserCertificateChallenge {
                                transaction_id,
                                challenge_id,
                                origin,
                                chain,
                            },
                        },
                    );
                    // TRUE plus a strong certificate reference is WebKit's asynchronous
                    // handling contract. The failed load ends; acceptance explicitly reloads.
                    true
                }),
            );
            let initialized = {
                let s = state.borrow();
                super::attached(&s.request, &s.sender)
            };
            if initialized.is_err() {
                fail(
                    &state,
                    "Could not start the attached native authentication window",
                );
            }
        })
        .map_err(|_| Error::invalid("Could not attach native WebKit authentication handlers"))
}
pub(super) fn certificate_decision(
    window: &WebviewWindow,
    challenge_id: Uuid,
    accept: bool,
) -> Result<()> {
    let label = window.label().to_owned();
    window
        .with_webview(move |_| {
            let state = WINDOWS.with(|windows| windows.borrow().get(&label).cloned());
            let Some(state) = state else {
                return;
            };
            let challenge = {
                let mut s = state.borrow_mut();
                if s.closed
                    || s.pending
                        .as_ref()
                        .is_none_or(|c| c.id != challenge_id || c.generation != s.generation)
                {
                    return;
                }
                s.pending.take().unwrap()
            };
            if !accept {
                fail(&state, "Browser TLS certificate was rejected");
                return;
            }
            let Some(view) = state.borrow().view.upgrade() else {
                return;
            };
            let Some(context) = view.context() else {
                fail(&state, "Browser context is unavailable");
                return;
            };
            context.allow_tls_certificate_for_host(&challenge.certificate, &challenge.host);
            view.load_uri(challenge.uri.as_str());
        })
        .map_err(|_| Error::invalid("Could not deliver native WebKit certificate decision"))
}
pub(super) fn close(window: &WebviewWindow) -> Result<()> {
    let label = window.label().to_owned();
    window
        .with_webview(move |native| {
            if let Some(state) = WINDOWS.with(|windows| windows.borrow_mut().remove(&label)) {
                let mut s = state.borrow_mut();
                s.closed = true;
                s.pending = None;
                s.cancel.cancel();
                if let Some(timer) = s.timer.take() {
                    timer.remove();
                }
                for signal in s.signals.drain(..) {
                    disconnect(signal);
                }
                if let Some(signal) = s.resource_signal.take() {
                    disconnect(signal);
                }
            }
            native.inner().stop_loading();
        })
        .map_err(|_| Error::invalid("Could not release native WebKit authentication handlers"))
}
