use ocvpn_model::{ipc::*, *};
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::Zeroizing;

#[test]
fn certificate_pins_require_complete_hashes_not_native_prefix_matches() {
    for fingerprint in ["pin-sha256:AAAA", "sha256:0000", "0000"] {
        assert!(CertificatePin::new("vpn.example", 443, fingerprint.into()).is_err());
    }
    let full = format!("pin-sha256:{}=", "A".repeat(43));
    assert!(CertificatePin::new("vpn.example", 443, full).is_ok());
}

#[test]
fn profiles_preserve_paths_and_future_protocols_without_connecting_them() {
    let url = parse_server("[::1]:8443/pulse/session").unwrap();
    assert_eq!(url.as_str(), "https://[::1]:8443/pulse/session");
    let mut profile = Profile::new("Office".into(), url, "future-protocol".into());
    profile.validate().unwrap();
    assert_eq!(
        profile.validate_for_connect(&[]).unwrap_err().code,
        ErrorCode::UnsupportedProtocol
    );
    profile.mtu = Some(1279);
    assert!(profile.validate().is_err());
    profile.disable_ipv6 = true;
    profile.validate().unwrap();
    for server in [
        "http://vpn.test",
        "https://user:secret@vpn.test",
        "https://vpn.test/#token",
        "https://vpn.test:0",
    ] {
        assert!(parse_server(server).is_err());
    }
}

#[test]
fn certificate_references_keep_pin_material_out_of_metadata() {
    let mut profile = Profile::new(
        "Token".into(),
        parse_server("vpn.example").unwrap(),
        "anyconnect".into(),
    );
    for uri in [
        "pkcs11:token=Office?pin-value=123456",
        "PKCS11:token=Office?PIN-SOURCE=file%3A%2Fprivate%2Fpin",
        "pkcs11:token=Office;pin-value=%31%32%33",
        "pkcs11:token=Office;pinfile=/private/pin",
        " p k c s 1 1 :token=Office?pin - source=|command",
        "pkcs11:token=Office?%70in-value=123456",
    ] {
        for field in 0..5 {
            let mut candidate = profile.clone();
            let reference = match field {
                0 => &mut candidate.ca_file,
                1 => &mut candidate.client_certificate,
                2 => &mut candidate.client_key,
                3 => &mut candidate.secondary_certificate,
                _ => &mut candidate.secondary_key,
            };
            *reference = Some(uri.into());
            assert_eq!(
                candidate.validate().unwrap_err().code,
                ErrorCode::InvalidInput
            );
        }
    }
    // Attribute-looking text inside values is not a PIN attribute; paths
    // and binary PKCS#11 object identifiers must retain their exact bytes.
    for reference in [
        "/home/user/pin-value=certificate.pem",
        r"C:\certificates\pin-source=key.pem",
        "pkcs11:object=pin-value%3D123;id=%00%ff;type=private?module-name=opensc",
        "pkcs11:token=Office;object=pin-source&not-an-attribute",
    ] {
        profile.client_key = Some(reference.into());
        profile.validate().unwrap();
        let decoded: Profile =
            serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
        assert_eq!(decoded.client_key.as_deref(), Some(reference));
    }
}

#[test]
fn authentication_rounds_reject_stale_or_unoffered_answers() {
    let prompt = AuthPrompt {
        prompt_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        auth_id: "gateway".into(),
        banner: None,
        message: None,
        error: None,
        fields: vec![AuthField {
            name: "group".into(),
            label: "Gateway".into(),
            kind: AuthFieldKind::Select,
            required: true,
            numeric: false,
            choices: vec![AuthChoice {
                id: "bar".into(),
                label: "Bar".into(),
            }],
        }],
    };
    let mut reply = AuthReply {
        prompt_id: prompt.prompt_id,
        attempt_id: prompt.attempt_id,
        answers: Some(BTreeMap::from([(
            "group".into(),
            Zeroizing::new("bar".into()),
        )])),
    };
    prompt.validate_reply(&reply).unwrap();
    reply.prompt_id = Uuid::new_v4();
    assert_eq!(
        prompt.validate_reply(&reply).unwrap_err().code,
        ErrorCode::Conflict
    );
    reply.prompt_id = prompt.prompt_id;
    reply
        .answers
        .as_mut()
        .unwrap()
        .insert("group".into(), Zeroizing::new("removed".into()));
    assert_eq!(
        prompt.validate_reply(&reply).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    reply.answers = None;
    prompt.validate_reply(&reply).unwrap();
}

#[tokio::test]
async fn framing_rejects_oversize_truncation_unknown_methods_and_versions() {
    for bytes in [
        ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec(),
        vec![0, 0, 0, 8, b'{'],
        vec![0, 0],
    ] {
        let result: Result<Hello> = read_frame(&mut bytes.as_slice()).await;
        assert_eq!(result.unwrap_err().code, ErrorCode::ProtocolViolation);
    }
    let mut buffer = Vec::new();
    write_frame(&mut buffer, &serde_json::json!({"request_id": Uuid::new_v4(), "method": "execute", "params": {"command": "bad"}})).await.unwrap();
    assert!(
        read_frame::<_, Request>(&mut buffer.as_slice())
            .await
            .is_err()
    );
    assert!(Hello { version: 2 }.validate().is_err());
    let mut stream = Vec::new();
    write_frame(
        &mut stream,
        &Request {
            request_id: Uuid::new_v4(),
            method: Method::Capabilities,
        },
    )
    .await
    .unwrap();
    let request: Request = read_frame(&mut stream.as_slice()).await.unwrap();
    assert!(matches!(request.method, Method::Capabilities));
}

#[tokio::test]
async fn writer_rejects_oversize_before_emitting_a_partial_frame() {
    let mut stream = Vec::new();
    let error = write_frame(&mut stream, &"x".repeat(MAX_FRAME_BYTES))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolViolation);
    assert!(stream.is_empty());
}

#[test]
fn connecting_requires_authentication_and_network_completion() {
    let mut state = ConnectionState::Disconnected;
    assert!(state.transition(ConnectionState::Connected).is_err());
    state.transition(ConnectionState::Authenticating).unwrap();
    assert!(state.transition(ConnectionState::Connected).is_err());
    state.transition(ConnectionState::Connecting).unwrap();
    state.transition(ConnectionState::Connected).unwrap();
    state.transition(ConnectionState::Reconnecting).unwrap();
    state
        .transition(ConnectionState::AuthenticationRequired)
        .unwrap();
    assert!(state.transition(ConnectionState::Connected).is_err());
}

#[tokio::test]
async fn secret_handoff_retains_pulse_path_and_proxy_dns_fallback() {
    let protocols = vec![ProtocolInfo {
        id: "pulse".into(),
        label: "Pulse".into(),
        description: String::new(),
        flags: 0,
    }];
    let handoff = AuthHandoff {
        protocol: "pulse".into(),
        connect_url: parse_server("[::1]:8443/session/negotiated").unwrap(),
        dns_name: "vpn.example".into(),
        peer_address: None,
        peer_fingerprint: format!("pin-sha256:{}=", "A".repeat(43)),
        cookie: Zeroizing::new("private-cookie".into()),
        expires_at: Some(2000),
        proxy_credentials: None,
        tunnel_options: TunnelOptions {
            proxy: Some(url::Url::parse("http://proxy.example:8080").unwrap()),
            sni: Some("vpn.example".into()),
            user_agent: None,
            reported_os: None,
            mtu: None,
            disable_dtls: false,
            disable_ipv6: false,
            reconnect_timeout_secs: 300,
        },
    };
    handoff.validate(&protocols, 1000).unwrap();
    let mut bytes = Zeroizing::new(Vec::new());
    let attempt_id = Uuid::new_v4();
    write_frame(
        &mut *bytes,
        &Request {
            request_id: Uuid::new_v4(),
            method: Method::Start {
                attempt_id,
                handoff,
            },
        },
    )
    .await
    .unwrap();
    let decoded: Request = read_frame(&mut bytes.as_slice()).await.unwrap();
    let Method::Start {
        mut handoff,
        attempt_id: received,
    } = decoded.method
    else {
        panic!("Wrong IPC method")
    };
    assert_eq!(received, attempt_id);
    assert_eq!(
        handoff.connect_url.as_str(),
        "https://[::1]:8443/session/negotiated"
    );
    assert_eq!(handoff.dns_name, "vpn.example");
    assert_eq!(handoff.peer_address, None);
    handoff.peer_fingerprint = "pin-sha256:AAAA".into();
    assert!(handoff.validate(&protocols, 1000).is_err());
    assert_eq!(
        handoff.tunnel_options.proxy.unwrap().host_str(),
        Some("proxy.example")
    );
}

#[test]
fn network_contract_rejects_invalid_prefixes_and_dns_injection() {
    assert!(
        IpPrefix {
            address: "::1".parse().unwrap(),
            prefix: 129
        }
        .validate()
        .is_err()
    );
    assert!(
        IpPrefix {
            address: "192.0.2.1".parse().unwrap(),
            prefix: 33
        }
        .validate()
        .is_err()
    );
    for domain in [
        "a;touch /tmp/file",
        "a\nb",
        ".example",
        "a..example",
        "-bad.example",
    ] {
        assert!(validate_domain(domain).is_err());
    }
    validate_domain("xn--bcher-kva.example.").unwrap();
}
