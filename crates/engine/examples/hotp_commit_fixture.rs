//! Development-only failure injection at the durable HOTP commit boundary.
use ocvpn_engine::{
    Engine,
    auth::{AuthEvent, AuthSecrets, TokenCallbacks},
};
use ocvpn_model::{Error, ErrorCode, Profile, Result, TokenMode};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

// Public RFC 4226 test key; never a user's token seed.
const TEST_SEED: &str = "12345678901234567890,0";
#[derive(Default)]
struct FailedCommit {
    locks: AtomicUsize,
    commits: AtomicUsize,
}
impl TokenCallbacks for FailedCommit {
    fn lock(&self) -> Result<Option<Zeroizing<String>>> {
        self.locks.fetch_add(1, Ordering::SeqCst);
        Ok(Some(Zeroizing::new(TEST_SEED.into())))
    }
    fn unlock(&self, token: Option<&str>) -> Result<()> {
        if !token.is_some_and(|value| value.ends_with(",1")) {
            return Err(Error::invalid(
                "Native HOTP did not advance the expected fixture counter",
            ));
        }
        self.commits.fetch_add(1, Ordering::SeqCst);
        Err(Error::new(
            ErrorCode::KeyringUnavailable,
            "Injected durable counter write failure",
        ))
    }
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().ok_or("native root required")?);
    let profile_path = PathBuf::from(args.next().ok_or("private fixture profile required")?);
    if args.next().is_some() {
        return Err("unexpected arguments".into());
    }
    let mut profile: Profile = serde_json::from_reader(std::fs::File::open(profile_path)?)?;
    profile.token_mode = TokenMode::Hotp;
    let callbacks = Arc::new(FailedCommit::default());
    let engine = unsafe { Engine::load_for_development(&root)? };
    let task = engine.authenticate(
        Uuid::new_v4(),
        profile,
        vec![],
        AuthSecrets {
            password: Some(Zeroizing::new("test".into())),
            token_seed: Some(Zeroizing::new(TEST_SEED.into())),
            token_callbacks: Some(callbacks.clone()),
            ..AuthSecrets::default()
        },
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match task.recv_timeout(Duration::from_millis(100))? {
            None => continue,
            Some(AuthEvent::Failed(error)) if error.code == ErrorCode::KeyringUnavailable => {
                if callbacks.locks.load(Ordering::SeqCst) != 1
                    || callbacks.commits.load(Ordering::SeqCst) != 1
                {
                    return Err("HOTP persistence boundary was not exercised exactly once".into());
                }
                println!("{{\"schema_version\":1,\"hotp_commit_failure\":true}}");
                return Ok(());
            }
            Some(_) => {
                return Err(
                    "Native authentication continued or failed outside the HOTP commit boundary"
                        .into(),
                );
            }
        }
    }
    Err("HOTP fixture timed out".into())
}
