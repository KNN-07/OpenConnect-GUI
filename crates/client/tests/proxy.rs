use ocvpn_client::proxy::parse_proxy;

#[test]
fn credential_userinfo_never_enters_proxy_metadata() {
    let parsed = parse_proxy("http://alice:p%40ss:word@[::1]:8080").unwrap();
    assert_eq!(parsed.endpoint.as_str(), "http://[::1]:8080/");
    let values: Vec<String> = serde_json::from_str(parsed.credentials.as_ref().unwrap()).unwrap();
    assert_eq!(values, ["alice", "p%40ss:word"]);
    assert!(parse_proxy("http://alice:secret@proxy.example/path").is_err());
    assert!(parse_proxy("http://alice:secret@proxy.example#fragment").is_err());
}
