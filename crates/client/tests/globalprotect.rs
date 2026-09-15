use base64::{Engine, engine::general_purpose::STANDARD};
use ocvpn_client::globalprotect::{decode_callback, parse_completion};
use ocvpn_model::ErrorCode;

fn completion(cookie_name: &str, cookie: &str) -> String {
    format!(
        "<saml-auth-status>1</saml-auth-status><saml-username>alice@example.test</saml-username><{cookie_name}>{cookie}</{cookie_name}>"
    )
}

#[test]
fn fixture_comment_only_completion_preserves_native_cookie_kind() {
    for cookie_name in ["prelogin-cookie", "portal-userauthcookie"] {
        // OpenConnect 9.21 tests/fake-gp-server.py /saml-login success response.
        let html = format!(
            "<html><body>Login Successful!</body><!-- {} --></html>",
            completion(cookie_name, "opaque&amp;cookie&#x2b;")
        );
        let result = parse_completion(&html).unwrap();
        assert_eq!(result.username.as_str(), "alice@example.test");
        assert_eq!(result.cookie_name, cookie_name);
        assert_eq!(result.cookie.as_str(), "opaque&cookie+");
    }
}

#[test]
fn custom_callback_requires_exact_scheme_and_valid_utf8_base64() {
    let html = completion("prelogin-cookie", "secret");
    let encoded = STANDARD.encode(&html);
    for prefix in [
        "globalprotectcallback:",
        "globalprotectcallback:/",
        "globalprotectcallback://",
    ] {
        let decoded = decode_callback(&format!("{prefix}{encoded}")).unwrap();
        assert_eq!(decoded.as_str(), html);
        assert_eq!(
            parse_completion(&decoded).unwrap().cookie.as_str(),
            "secret"
        );
    }
    for input in [
        encoded,
        format!("https://vpn.test/{html}"),
        format!("GLOBALPROTECTCALLBACK:{}", STANDARD.encode(&html)),
        "globalprotectcallback:%%%".into(),
        "globalprotectcallback:/".into(),
        "globalprotectcallback:/w==".into(),
        format!("globalprotectcallback:{}%3D", STANDARD.encode(&html)),
    ] {
        assert!(decode_callback(&input).is_err());
    }
}

#[test]
fn duplicate_and_contradictory_fields_never_choose_a_credential() {
    let valid = completion("prelogin-cookie", "secret");
    for extra in [
        "<saml-auth-status>1</saml-auth-status>",
        "<saml-auth-status>0</saml-auth-status>",
        "<saml-username>alice@example.test</saml-username>",
        "<prelogin-cookie>secret</prelogin-cookie>",
        "<portal-userauthcookie>different</portal-userauthcookie>",
        "<!-- <prelogin-cookie>hidden-conflict</prelogin-cookie> -->",
    ] {
        assert!(parse_completion(&format!("{valid}{extra}")).is_err());
    }
    assert!(parse_completion(&valid.replace(">1<", ">0<")).is_err());
    assert!(parse_completion(&valid.replace("alice@example.test", " ")).is_err());
    assert!(parse_completion(&completion("prelogin-cookie", " ")).is_err());
}

#[test]
fn rejects_malformed_markup_entity_expansion_and_header_injection() {
    for input in [
        format!(
            "<!DOCTYPE html [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>{}",
            completion("prelogin-cookie", "&x;")
        ),
        format!(
            "<!DOCTYPE html [<!ENTITY x 'a'><!ENTITY y '&x;&x;'>]>{}",
            completion("prelogin-cookie", "&y;")
        ),
        completion("prelogin-cookie", "&unknown;"),
        completion("prelogin-cookie", "&#0;"),
        completion("prelogin-cookie", "&#13;&#10;Injected: yes"),
        completion("prelogin-cookie", "<b>nested</b>"),
        completion("prelogin-cookie", "<!-- concealed -->secret"),
        completion("prelogin-cookie", "secret").replace("</prelogin-cookie>", "</other>"),
        format!("<html>{}", completion("prelogin-cookie", "secret")),
        format!(
            "<html data='&external;'>{}</html>",
            completion("prelogin-cookie", "secret")
        ),
    ] {
        assert!(parse_completion(&input).is_err());
    }
}

#[test]
fn inert_html_cannot_supply_completion_fields() {
    let valid = completion("prelogin-cookie", "secret");
    for tag in ["script", "SCRIPT", "style", "template", "textarea"] {
        assert!(parse_completion(&format!("<html><{tag}>{valid}</{tag}></html>")).is_err());
        let visible = format!(
            "<html><{tag}>{}</{tag}><br><meta charset='utf-8'>{valid}</html>",
            completion("prelogin-cookie", "wrong")
        );
        assert_eq!(
            parse_completion(&visible).unwrap().cookie.as_str(),
            "secret"
        );
    }
}

#[test]
fn cas_token_is_an_upstream_limitation_not_a_cookie() {
    for input in [
        "globalprotectcallback:cas-as=1&un=alice&token=secret",
        "globalprotectcallback://cas-as%3D1%26un%3Dalice%26token%3Dsecret",
    ] {
        let error = decode_callback(input).err().unwrap();
        assert_eq!(error.code, ErrorCode::UnsupportedAuthentication);
    }
    let error = parse_completion("<cas-as>1</cas-as><token>secret</token>")
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::UnsupportedAuthentication);
}

#[test]
fn bounded_resources_and_errors_do_not_disclose_secrets() {
    let secret = "unique-private-credential-9387";
    let valid = completion("prelogin-cookie", secret);
    let oversized = "x".repeat(1024 * 1024 + 1);
    let deep = format!("{}{}{}", "<x>".repeat(65), valid, "</x>".repeat(65));
    let many = format!("{}{valid}", "<x/>".repeat(32_768));
    for input in [
        oversized.clone(),
        deep,
        many,
        format!("{valid}<{secret}>"),
        completion("prelogin-cookie", &format!("&{secret};")),
    ] {
        let error = parse_completion(&input).err().unwrap();
        assert!(!format!("{error:?}").contains(secret));
        assert!(!error.to_string().contains(secret));
        assert!(error.details.is_none());
    }
    assert!(decode_callback(&format!("globalprotectcallback:{oversized}")).is_err());
    let error = decode_callback(&format!("globalprotectcallback:{secret}%"))
        .err()
        .unwrap();
    assert!(!format!("{error:?}").contains(secret));
}
