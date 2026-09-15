//! Verify the real native browser-chain policy using fresh fixture certificates.
use ocvpn_engine::Engine;
use ocvpn_model::{BrowserTlsPolicy, CertificatePin};
#[cfg(unix)]
use std::os::fd::AsFd;
use std::{io::Read, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let native = PathBuf::from(args.next().ok_or("native root required")?);
    let der = PathBuf::from(args.next().ok_or("fixture DER certificate required")?);
    let ca = PathBuf::from(args.next().ok_or("fixture CA required")?);
    if args.next().is_some() {
        return Err("unexpected arguments".into());
    }
    let mut certificate = Vec::new();
    std::fs::File::open(der)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut certificate)?;
    let chain = vec![certificate];
    let engine = unsafe { Engine::load_for_development(&native)? };
    let origin = "https://127.0.0.1:8443/".parse()?;
    let mut policy = BrowserTlsPolicy {
        ca_file: Some(ca.to_str().ok_or("CA path is not UTF-8")?.into()),
        pins: vec![],
    };
    #[cfg(unix)]
    assert!(
        std::io::stdin().as_fd().try_clone_to_owned().is_ok(),
        "fixture stdin must be open"
    );
    let trusted = engine.verify_browser_chain(&origin, &chain, &policy)?;
    assert!(trusted.trusted);
    #[cfg(unix)]
    assert!(
        std::io::stdin().as_fd().try_clone_to_owned().is_ok(),
        "native verification closed a caller-owned descriptor"
    );
    assert!(
        !engine
            .verify_browser_chain(&"https://wrong.invalid/".parse()?, &chain, &policy)?
            .trusted
    );
    policy.ca_file = None;
    assert!(
        !engine
            .verify_browser_chain(&origin, &chain, &policy)?
            .trusted
    );
    policy
        .pins
        .push(CertificatePin::new("127.0.0.1", 8443, trusted.fingerprint)?);
    assert!(
        engine
            .verify_browser_chain(&origin, &chain, &policy)?
            .trusted
    );
    policy.pins[0].port = 8444;
    assert!(
        !engine
            .verify_browser_chain(&origin, &chain, &policy)?
            .trusted
    );
    policy.pins[0].port = 8443;
    policy.pins[0].fingerprint = format!("pin-sha256:{}=", "A".repeat(43));
    // A valid private CA cannot bypass a mismatching explicit pin.
    policy.ca_file = Some(ca.to_str().unwrap().into());
    let mismatch = engine.verify_browser_chain(&origin, &chain, &policy)?;
    assert!(!mismatch.trusted && mismatch.changed_pin);
    println!(
        "{{\"schema_version\":1,\"passed\":true,\"coverage\":\"native_browser_chain_trust_and_host_scoped_pins\"}}"
    );
    Ok(())
}
