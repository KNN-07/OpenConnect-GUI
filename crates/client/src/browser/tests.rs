use super::*;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ocvpn-browser-replay-{}", Uuid::new_v4()));
        private_fs::ensure_private_directory(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn consumed_callback_survives_reload_without_persisting_the_cookie() {
    let fixture = Fixture::new();
    let path = fixture.0.join("consumed-callbacks.json");
    let cookie = "private-callback-credential-never-persist";
    claim_completion_at(&path, cookie, 100).unwrap();
    assert_eq!(
        claim_completion_at(&path, cookie, 101).unwrap_err().code,
        ErrorCode::AuthenticationRejected
    );
    assert!(
        !String::from_utf8(fs::read(&path).unwrap())
            .unwrap()
            .contains(cookie)
    );
    private_fs::atomic_write(&path, b"broken replay ledger", true).unwrap();
    assert_eq!(
        claim_completion_at(&path, "another-credential", 102)
            .unwrap_err()
            .code,
        ErrorCode::CorruptStorage
    );
    assert_eq!(fs::read(&path).unwrap(), b"broken replay ledger");
}

fn page(headers: &[(&str, &str)], document: Option<&str>) -> BrowserPage {
    BrowserPage {
        uri: SecretText::new("https://vpn.example.test/complete".into()),
        cookies: vec![],
        headers: headers
            .iter()
            .map(|(name, value)| {
                (
                    SecretText::new((*name).into()),
                    SecretText::new((*value).into()),
                )
            })
            .collect(),
        document: document.map(|value| SecretText::new(value.into())),
    }
}

#[test]
fn completion_requires_one_consistent_successful_response() {
    let mut complete = page(
        &[
            ("saml-auth-status", "1"),
            ("saml-username", "account"),
            ("prelogin-cookie", "credential"),
        ],
        None,
    );
    let result = page_completion(&complete).unwrap().unwrap();
    assert_eq!(result.username.as_str(), "account");
    assert_eq!(result.cookie_name, "prelogin-cookie");
    assert_eq!(result.cookie.as_str(), "credential");
    complete.headers.push((
        SecretText::new("SAML-USERNAME".into()),
        SecretText::new("other-account".into()),
    ));
    assert!(page_completion(&complete).is_err());
    assert!(page_completion(&page(&[("saml-auth-status", "1")], None)).is_err());
    assert!(
        page_completion(&page(
            &[
                ("saml-auth-status", "0"),
                ("saml-username", "account"),
                ("prelogin-cookie", "credential")
            ],
            None
        ))
        .is_err()
    );
}

#[test]
fn ordinary_login_page_waits_but_incomplete_completion_is_rejected() {
    assert!(
        page_completion(&page(
            &[],
            Some("<html><form><input name='username'><input type='password'></form></html>")
        ))
        .unwrap()
        .is_none()
    );
    assert!(
        page_completion(&page(
            &[],
            Some("<!-- <prelogin-cookie>credential</prelogin-cookie> -->")
        ))
        .is_err()
    );
}
