use base64::{Engine, engine::general_purpose::STANDARD};
use ocvpn_client::browser_bootstrap::{Bootstrap, bind};
use ocvpn_model::{ErrorCode, MAX_BROWSER_BYTES};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};

fn endpoint(bootstrap: &Bootstrap) -> (String, String) {
    let url = url::Url::parse(bootstrap.url.as_str()).unwrap();
    (
        format!("127.0.0.1:{}", url.port().unwrap()),
        url.path().to_owned(),
    )
}

async fn request(address: &str, method: &str, path: &str, host: &str) -> String {
    timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn head_preserves_get_and_success_closes_replay_listener() {
    let target = "https://vpn.example.test/saml?opaque=credential";
    let mut bootstrap = bind(target).await.unwrap();
    let (address, path) = endpoint(&bootstrap);
    let head = request(&address, "HEAD", &path, &address).await;
    assert!(head.starts_with("HTTP/1.1 302 "));
    assert!(head.contains(&format!("Location: {target}\r\n")));
    assert!(head.ends_with("\r\n\r\n"));
    assert!(matches!(
        bootstrap.finished.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let get = request(&address, "GET", &path, &address).await;
    assert!(get.starts_with("HTTP/1.1 302 "));
    assert!(get.contains("Cache-Control: no-store\r\n"));
    assert!(get.contains("Referrer-Policy: no-referrer\r\n"));
    timeout(Duration::from_secs(2), &mut bootstrap.finished)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(TcpStream::connect(&address).await.is_err());
}

#[tokio::test]
async fn wrong_path_method_and_host_do_not_consume_html() {
    let html = "<html><body><form method=\"post\" action=\"https://vpn.example.test/saml\"><input name=\"SAMLResponse\" value=\"opaque\"></form></body></html>";
    let mut bootstrap = bind(&format!("data:text/html;base64,{}", STANDARD.encode(html)))
        .await
        .unwrap();
    let (address, path) = endpoint(&bootstrap);
    for (method, target, host, status) in [
        ("GET", "/wrong", address.as_str(), 404),
        ("POST", path.as_str(), address.as_str(), 405),
        ("GET", path.as_str(), "attacker.example.test", 400),
        ("GET", path.as_str(), "127.0.0.1", 400),
    ] {
        let response = request(&address, method, target, host).await;
        assert!(response.starts_with(&format!("HTTP/1.1 {status} ")));
        assert!(!response.contains(html));
    }
    let head = request(&address, "HEAD", &path, &address).await;
    assert!(head.starts_with("HTTP/1.1 200 "));
    assert!(!head.contains(html));
    let get = request(&address, "GET", &path, &address).await;
    assert!(get.contains("Content-Type: text/html; charset=utf-8\r\n"));
    assert_eq!(get.split_once("\r\n\r\n").unwrap().1, html);
    timeout(Duration::from_secs(2), &mut bootstrap.finished)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn dropping_owner_closes_listener_and_partial_connection() {
    let bootstrap = bind("https://vpn.example.test/auth").await.unwrap();
    let (address, _) = endpoint(&bootstrap);
    let mut stream = TcpStream::connect(&address).await.unwrap();
    stream.write_all(b"GET /").await.unwrap();
    tokio::task::yield_now().await;
    drop(bootstrap);
    let mut byte = [0u8; 1];
    let result = timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    assert!(TcpStream::connect(&address).await.is_err());
}

#[tokio::test]
async fn rejects_unsafe_schemes_credentials_and_unbounded_payloads() {
    for input in [
        "http://vpn.example.test/auth",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<html></html>",
        "data:text/html;base64,%%%",
        "data:text/html;base64,",
        "https://user:secret@vpn.example.test/",
        "https://vpn.example.test/\r\nX-Leak: secret",
        "https://vpn.example.test\\@attacker.example.test/",
        "<form></form>",
    ] {
        assert!(matches!(bind(input).await, Err(error) if error.code == ErrorCode::InvalidInput));
    }
    let oversized = "x".repeat(MAX_BROWSER_BYTES + 1);
    assert!(matches!(bind(&oversized).await, Err(error) if error.code == ErrorCode::InvalidInput));
}
