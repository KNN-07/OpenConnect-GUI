//! Drives real client/browser/native authentication; page interaction stays native.
use ocvpn_client::auth::{self, AuthEvent, AuthInputs};
use ocvpn_model::{
    AuthFieldKind, AuthReply, BrowserStage, CertificateDecision, ErrorCode, Profile, SecretText,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    profile: Profile,
    password: Option<SecretText>,
    #[serde(default)]
    expected_error: Option<ErrorCode>,
    #[serde(default)]
    cancel_at_waiting: bool,
    #[serde(default)]
    browser_accounts: Vec<String>,
    #[serde(default)]
    browser_timeout_seconds: Option<u64>,
}
fn emit(value: serde_json::Value) {
    println!("{value}");
    let _ = std::io::stdout().flush();
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().ok_or("Native root required")?);
    let input = PathBuf::from(args.next().ok_or("Private fixture input required")?);
    let gui = PathBuf::from(args.next().ok_or("Trusted desktop executable required")?);
    if args.next().is_some() {
        return Err("Unexpected fixture arguments".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(input)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("Fixture input too large".into());
    }
    let fixture: Fixture = serde_json::from_slice(&bytes).map_err(|_| "Invalid fixture input")?;
    let expected_account = fixture
        .profile
        .username
        .clone()
        .ok_or("Fixture account required")?;
    let mut session = unsafe {
        auth::begin_for_development(
            &root,
            Uuid::new_v4(),
            fixture.profile,
            AuthInputs {
                password: fixture.password.map(|value| value.0),
                ..Default::default()
            },
        )?
    };
    unsafe {
        session.set_gui_for_development(&gui)?;
    }
    if let Some(seconds) = fixture.browser_timeout_seconds {
        session.set_browser_timeout_for_development(Duration::from_secs(seconds))?;
    }
    let control = session.control();
    let mut confirmed = 0;
    let mut phases = Vec::new();
    let mut final_account = expected_account.clone();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if Instant::now() > deadline {
            control.cancel();
            return Err("Native browser fixture timed out".into());
        }
        match session.recv_timeout(Duration::from_millis(100))? {
            None => {}
            Some(AuthEvent::Browser(prompt)) => {
                emit(
                    serde_json::json!({"event":"browser", "stage":prompt.stage, "phase":prompt.phase}),
                );
                if fixture.cancel_at_waiting && prompt.stage == BrowserStage::Waiting {
                    control.cancel();
                }
                if prompt.stage == BrowserStage::ConfirmAccount {
                    let account = fixture
                        .browser_accounts
                        .get(confirmed)
                        .unwrap_or(&expected_account);
                    if prompt.account.as_deref() != Some(account.as_str()) {
                        control.cancel();
                        return Err("Unexpected browser account".into());
                    }
                    final_account = account.clone();
                    control.browser_confirm(prompt.transaction_id, true)?;
                    confirmed += 1;
                    phases.push(prompt.phase);
                }
            }
            Some(AuthEvent::BrowserFinished(_)) => {
                emit(serde_json::json!({"event":"browser_closed"}))
            }
            Some(AuthEvent::Prompt(prompt)) => {
                let mut answers = BTreeMap::new();
                for field in &prompt.fields {
                    if field.kind != AuthFieldKind::Select || field.choices.len() != 1 {
                        return Err("Unexpected non-browser authentication form".into());
                    }
                    answers.insert(
                        field.name.clone(),
                        Zeroizing::new(field.choices[0].id.clone()),
                    );
                }
                control.reply(AuthReply {
                    attempt_id: prompt.attempt_id,
                    prompt_id: prompt.prompt_id,
                    answers: Some(answers),
                })?;
            }
            Some(AuthEvent::Certificate(prompt)) => {
                control.certificate_reply(prompt.prompt_id, CertificateDecision::Reject)?
            }
            Some(AuthEvent::Authenticated(handoff)) => {
                if fixture.expected_error.is_some() || handoff.cookie.is_empty() || confirmed == 0 {
                    return Err("Unexpected native browser completion".into());
                }
                if !fixture.browser_accounts.is_empty()
                    && confirmed != fixture.browser_accounts.len()
                {
                    return Err("An independent SAML round was not requested".into());
                }
                if !url::form_urlencoded::parse(handoff.cookie.as_bytes())
                    .any(|(name, value)| name == "user" && value == final_account)
                {
                    return Err(
                        "Native handoff account differs from the confirmed browser account".into(),
                    );
                }
                emit(
                    serde_json::json!({"schema_version":1,"event":"authenticated","confirmed":confirmed,"phases":phases}),
                );
                return Ok(());
            }
            Some(AuthEvent::Failed(error)) => {
                emit(serde_json::json!({"event":"failed","code":error.code,"error":&error}));
                if fixture.expected_error == Some(error.code) {
                    return Ok(());
                }
                return Err("Real browser authentication failed".into());
            }
            Some(AuthEvent::Cancelled) => {
                emit(serde_json::json!({"event":"cancelled"}));
                if fixture.cancel_at_waiting || fixture.expected_error == Some(ErrorCode::Cancelled)
                {
                    return Ok(());
                }
                return Err("Unexpected browser cancellation".into());
            }
        }
    }
}
