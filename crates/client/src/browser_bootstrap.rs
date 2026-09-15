//! One-shot loopback SAML bootstrap, with no browser launching or global ownership.
//!
//! Bounded bootstrap semantics adapted from GPL-3.0 GlobalProtect-openconnect,
//! commit 9e4f45997ebee452c58d7d3066dcfc175d65ef82,
//! crates/auth/src/browser/auth_server.rs (https://github.com/yuezk/GlobalProtect-openconnect).
//! Unlike that implementation, paths are unguessable and requests are strictly bounded.

use base64::{Engine, engine::general_purpose::STANDARD};
use ocvpn_model::{Error, ErrorCode, MAX_BROWSER_BYTES, Result, SecretText, https_origin};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{Duration, timeout},
};
use zeroize::Zeroizing;

const HEADER_LIMIT: usize = 16 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const PRIVACY_HEADERS: &str = "Cache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n";

/// Dropping this owner aborts the listener and its currently owned connection.
/// The completion receiver must be polled by reference so this owner stays alive.
pub struct Bootstrap {
    pub url: SecretText,
    pub finished: oneshot::Receiver<Result<()>>,
    task: JoinHandle<()>,
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Payload {
    Redirect(SecretText),
    Html(Zeroizing<Vec<u8>>),
}

fn invalid() -> Error {
    Error::invalid("Invalid or excessive browser bootstrap request")
}

fn runtime() -> Error {
    Error::new(
        ErrorCode::RuntimeFailure,
        "Browser bootstrap listener failed",
    )
}

/// Accept an HTTPS navigation or the native base64 HTML data URI. Raw HTML is
/// deliberately not accepted: callers must use the native explicit data type.
pub async fn bind(request: &str) -> Result<Bootstrap> {
    if request.is_empty() || request.len() > MAX_BROWSER_BYTES {
        return Err(invalid());
    }
    let payload = if let Some(encoded) = request.strip_prefix("data:text/html;base64,") {
        let mut html = Zeroizing::new(Vec::with_capacity(encoded.len() / 4 * 3 + 3));
        STANDARD
            .decode_vec(encoded, &mut html)
            .map_err(|_| invalid())?;
        if html.is_empty()
            || html.len() > MAX_BROWSER_BYTES
            || html.contains(&0)
            || std::str::from_utf8(&html).is_err()
        {
            return Err(invalid());
        }
        Payload::Html(html)
    } else {
        // Reject parser normalization that could change the apparent authority,
        // as well as every possible HTTP header injection character.
        if request
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        {
            return Err(invalid());
        }
        https_origin(request).map_err(|_| invalid())?;
        let parsed = url::Url::parse(request).map_err(|_| invalid())?;
        Payload::Redirect(SecretText::new(parsed.into()))
    };
    let mut random = Zeroizing::new([0u8; 32]);
    getrandom::fill(random.as_mut()).map_err(|_| runtime())?;
    let mut path = Zeroizing::new(String::with_capacity(65));
    path.push('/');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random.iter() {
        path.push(HEX[(byte >> 4) as usize] as char);
        path.push(HEX[(byte & 15) as usize] as char);
    }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| runtime())?;
    let authority = listener.local_addr().map_err(|_| runtime())?.to_string();
    let url = SecretText::new(format!("http://{authority}{}", path.as_str()));
    let (sender, finished) = oneshot::channel();
    let task = tokio::spawn(async move {
        let result = timeout(TOTAL_TIMEOUT, serve(listener, &authority, &path, &payload))
            .await
            .unwrap_or_else(|_| {
                Err(Error::new(
                    ErrorCode::AuthenticationRequired,
                    "Browser bootstrap timed out; start authentication again",
                ))
            });
        let _ = sender.send(result);
    });
    Ok(Bootstrap {
        url,
        finished,
        task,
    })
}

async fn serve(
    listener: TcpListener,
    authority: &str,
    path: &str,
    payload: &Payload,
) -> Result<()> {
    loop {
        let (mut stream, peer) = listener.accept().await.map_err(|_| runtime())?;
        if !peer.ip().is_loopback() {
            continue;
        }
        // A single owned connection avoids unbounded task creation. Slow or
        // malformed clients cannot extend either deadline or consume the GET.
        let mut consumed = false;
        match timeout(
            CONNECTION_TIMEOUT,
            respond(&mut stream, authority, path, payload, &mut consumed),
        )
        .await
        {
            Ok(Ok(true)) => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) if consumed => return Err(runtime()),
            _ => {}
        }
    }
}

async fn respond(
    stream: &mut TcpStream,
    authority: &str,
    path: &str,
    payload: &Payload,
    consumed: &mut bool,
) -> Result<bool> {
    let mut bytes = Zeroizing::new(vec![0u8; HEADER_LIMIT]);
    let mut used = 0;
    let end = loop {
        if used == HEADER_LIMIT {
            reject(stream, "431 Request Header Fields Too Large").await;
            return Ok(false);
        }
        let count = match stream.read(&mut bytes[used..]).await {
            Ok(0) | Err(_) => return Ok(false),
            Ok(count) => count,
        };
        used += count;
        if let Some(position) = bytes[..used].windows(4).position(|s| s == b"\r\n\r\n") {
            break position;
        }
    };
    let Ok(headers) = std::str::from_utf8(&bytes[..end]) else {
        reject(stream, "400 Bad Request").await;
        return Ok(false);
    };
    let mut lines = headers.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default();
    let target = request_line.next().unwrap_or_default();
    let version = request_line.next().unwrap_or_default();
    let mut valid = version == "HTTP/1.1" && request_line.next().is_none();
    let mut host = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            valid = false;
            break;
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
            || value.bytes().any(|c| (c < 32 && c != b'\t') || c == 127)
        {
            valid = false;
            break;
        }
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value.trim_matches([' ', '\t'])).is_some() {
                valid = false;
            }
        }
        // No request bodies, upgrades or transfer coding on this endpoint.
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("upgrade")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            valid = false;
        }
    }
    if !valid || host != Some(authority) {
        reject(stream, "400 Bad Request").await;
        return Ok(false);
    }
    if target != path {
        reject(stream, "404 Not Found").await;
        return Ok(false);
    }
    if method != "GET" && method != "HEAD" {
        reject(stream, "405 Method Not Allowed").await;
        return Ok(false);
    }
    *consumed = method == "GET";
    let capacity = match payload {
        Payload::Redirect(uri) => uri.as_str().len() + 512,
        Payload::Html(_) => 512,
    };
    let mut response = Zeroizing::new(String::with_capacity(capacity));
    use std::fmt::Write;
    match payload {
        Payload::Redirect(uri) => {
            write!(
                &mut *response,
                "HTTP/1.1 302 Found\r\n{PRIVACY_HEADERS}Location: {}\r\nContent-Length: 0\r\n\r\n",
                uri.as_str()
            )
            .map_err(|_| runtime())?;
        }
        Payload::Html(html) => {
            write!(&mut *response, "HTTP/1.1 200 OK\r\n{PRIVACY_HEADERS}Content-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n", html.len()).map_err(|_| runtime())?;
        }
    }
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|_| runtime())?;
    if method == "GET" {
        if let Payload::Html(html) = payload {
            stream.write_all(html).await.map_err(|_| runtime())?;
        }
    }
    stream.shutdown().await.map_err(|_| runtime())?;
    Ok(method == "GET")
}

async fn reject(stream: &mut TcpStream, status: &str) {
    let response = format!("HTTP/1.1 {status}\r\n{PRIVACY_HEADERS}Content-Length: 0\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}
