//! Development-only driver for pinned upstream TLS fixtures; never a runtime fallback.
use ocvpn_client::auth::{self, AuthEvent, AuthInputs};
use ocvpn_model::{AuthReply, CertificateDecision, ErrorCode, Profile};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(transparent)]
struct Answer(#[serde(deserialize_with = "answer")] Zeroizing<String>);
fn answer<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    profile: Profile,
    #[serde(default)]
    rounds: Vec<BTreeMap<String, Answer>>,
    #[serde(default)]
    password: Option<Answer>,
    #[serde(default)]
    token_seed: Option<Answer>,
    #[serde(default)]
    certificates: Vec<CertificateDecision>,
    #[serde(default)]
    expect_error: Option<ErrorCode>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().ok_or("native build root required")?);
    let path = PathBuf::from(args.next().ok_or("private fixture JSON required")?);
    if args.next().is_some() {
        return Err("Unexpected fixture driver arguments".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("Fixture input exceeds limit".into());
    }
    let fixture: Fixture =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid private fixture input")?;
    let protocol = fixture.profile.protocol.clone();
    let mut session = unsafe {
        auth::begin_for_development(
            &root,
            Uuid::new_v4(),
            fixture.profile,
            AuthInputs {
                password: fixture.password.map(|value| value.0),
                token_seed: fixture.token_seed.map(|value| value.0),
                ..AuthInputs::default()
            },
        )?
    };
    let control = session.control();
    let mut rounds = fixture.rounds.into_iter();
    let mut certificates = fixture.certificates.into_iter();
    let mut prompt_count = 0;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() > deadline {
            control.cancel();
            return Err("Fixture authentication timed out".into());
        }
        match session.recv_timeout(Duration::from_millis(100))? {
            None => continue,
            Some(AuthEvent::Prompt(prompt)) => {
                prompt_count += 1;
                let Some(answers) = rounds.next() else {
                    eprintln!(
                        "{}",
                        serde_json::json!({"auth_id": prompt.auth_id, "fields": prompt.fields.iter().map(|field|
                        serde_json::json!({"name":field.name,"kind":field.kind,"choices":field.choices})).collect::<Vec<_>>()})
                    );
                    control.cancel();
                    return Err(
                        "No private answers configured for the observed authentication round"
                            .into(),
                    );
                };
                control.reply(AuthReply {
                    prompt_id: prompt.prompt_id,
                    attempt_id: prompt.attempt_id,
                    answers: Some(
                        answers
                            .into_iter()
                            .map(|(name, value)| (name, value.0))
                            .collect(),
                    ),
                })?;
            }
            Some(AuthEvent::Certificate(prompt)) => {
                control.certificate_reply(
                    prompt.prompt_id,
                    certificates.next().unwrap_or(CertificateDecision::Reject),
                )?;
            }
            Some(AuthEvent::Authenticated(handoff)) => {
                if fixture.expect_error.is_some() {
                    return Err("Unexpected authentication success".into());
                }
                if rounds.next().is_some() {
                    return Err("Expected authentication rounds were not requested".into());
                }
                println!(
                    "{}",
                    serde_json::json!({"schema_version":1,"protocol":protocol,"authenticated":true,"prompt_count":prompt_count,"numeric_peer":handoff.peer_address.is_some()})
                );
                return Ok(());
            }
            Some(AuthEvent::Failed(error)) => {
                if fixture.expect_error == Some(error.code) {
                    println!(
                        "{}",
                        serde_json::json!({"schema_version":1,"protocol":protocol,"expected_error":error.code})
                    );
                    return Ok(());
                }
                eprintln!("{}", serde_json::to_string(&error)?);
                return Err("Native fixture authentication failed".into());
            }
            Some(AuthEvent::Browser(_)) => {
                return Err(
                    "Unexpected browser authentication; use the browser fixture driver".into(),
                );
            }
            Some(AuthEvent::BrowserFinished(_)) => continue,
            Some(AuthEvent::Cancelled) => {
                return Err("Native fixture authentication was cancelled".into());
            }
        }
    }
}
