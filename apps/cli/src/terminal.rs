use crate::{interrupted, runtime_error, terminal_text};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use ocvpn_client::connect::{ConnectEvent, Control};
use ocvpn_model::*;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
fn tty() -> Result<File> {
    #[cfg(unix)]
    let path = "/dev/tty";
    #[cfg(windows)]
    let path = "CONOUT$";
    OpenOptions::new().write(true).open(path).map_err(|_| {
        Error::new(
            ErrorCode::AuthenticationRequired,
            "A controlling terminal is required; connect interactively",
        )
    })
}
struct Raw;
impl Drop for Raw {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}
fn line(prompt: &str, secret: bool, stop: &AtomicBool) -> Result<Zeroizing<String>> {
    input(prompt, secret, stop, 65536)
}
fn input(prompt: &str, secret: bool, stop: &AtomicBool, limit: usize) -> Result<Zeroizing<String>> {
    let mut out = tty()?;
    write!(out, "{}: ", terminal_text(prompt))
        .and_then(|()| out.flush())
        .map_err(|_| runtime_error("Cannot write controlling terminal"))?;
    enable_raw_mode().map_err(|_| {
        Error::new(
            ErrorCode::AuthenticationRequired,
            "Cannot read controlling terminal",
        )
    })?;
    let _raw = Raw;
    let mut value = Zeroizing::new(String::with_capacity(limit));
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if stop.load(Ordering::Acquire) || Instant::now() > deadline {
            return Err(interrupted());
        }
        if !event::poll(Duration::from_millis(100))
            .map_err(|_| runtime_error("Terminal input failed"))?
        {
            continue;
        }
        match event::read().map_err(|_| runtime_error("Terminal input failed"))? {
            Event::Key(key) if key.kind != KeyEventKind::Release => match key.code {
                KeyCode::Enter => {
                    let _ = write!(out, "\r\n");
                    return Ok(value);
                }
                KeyCode::Esc => return Err(interrupted()),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err(interrupted());
                }
                KeyCode::Backspace => {
                    if let Some(c) = value.pop() {
                        let width = if secret {
                            1
                        } else {
                            unicode_width::UnicodeWidthChar::width(c).unwrap_or(0)
                        };
                        for _ in 0..width {
                            let _ = write!(out, "\x08 \x08");
                        }
                    }
                }
                KeyCode::Char(c) if !c.is_control() => {
                    if value.len() + c.len_utf8() > limit {
                        return Err(Error::invalid("Private input exceeds its size limit"));
                    }
                    value.push(c);
                    if secret {
                        let _ = write!(out, "*");
                    } else {
                        let _ = write!(out, "{c}");
                    }
                }
                _ => {}
            },
            _ => {}
        }
        let _ = out.flush();
    }
}
fn say(text: &str) -> Result<()> {
    writeln!(tty()?, "{}", terminal_text(text))
        .map_err(|_| runtime_error("Cannot write controlling terminal"))
}
pub fn confirm(text: &str, stop: &AtomicBool) -> Result<bool> {
    Ok(line(&format!("{text} [yes/no]"), false, stop)?.as_str() == "yes")
}
pub fn primary_password(stop: &AtomicBool) -> Result<Zeroizing<String>> {
    say(
        "This profile permits saving a primary password in the OS keyring only after successful authentication. Never enter an OTP here. Leave blank to reuse saved credentials or use session-only vendor prompts.",
    )?;
    line("Optional primary password to remember", true, stop)
}
pub fn interaction(event: ConnectEvent, control: Control, stop: Arc<AtomicBool>) -> Result<()> {
    match event {
        ConnectEvent::Prompt(prompt) => {
            for text in [&prompt.banner, &prompt.message, &prompt.error]
                .into_iter()
                .flatten()
            {
                say(text)?;
            }
            let mut answers = BTreeMap::new();
            for field in &prompt.fields {
                if matches!(field.kind, AuthFieldKind::SsoToken | AuthFieldKind::SsoUser) {
                    return Err(Error::new(
                        ErrorCode::UnsupportedAuthentication,
                        "SSO fields require the browser authentication flow",
                    ));
                }
                for choice in &field.choices {
                    say(&format!("  {} [{}]", choice.label, choice.id))?;
                }
                let value = line(
                    &field.label,
                    matches!(field.kind, AuthFieldKind::Password | AuthFieldKind::Token),
                    &stop,
                )?;
                answers.insert(field.name.clone(), value);
            }
            let reply = AuthReply {
                prompt_id: prompt.prompt_id,
                attempt_id: prompt.attempt_id,
                answers: Some(answers),
            };
            prompt.validate_reply(&reply)?;
            control.reply(reply)
        }
        ConnectEvent::Certificate(prompt) => {
            say(&format!(
                "Certificate for {}:{}\n{}\n{}\nFingerprint: {}{}",
                prompt.host,
                prompt.port,
                prompt.reason,
                prompt.details,
                prompt.fingerprint,
                if prompt.changed_pin {
                    " — CHANGED PIN"
                } else {
                    ""
                }
            ))?;
            let answer = line(
                "reject / accept (this attempt) / pin (exact host)",
                false,
                &stop,
            )?;
            let decision = match answer.as_str() {
                "accept" => CertificateDecision::AcceptAttempt,
                "pin" => CertificateDecision::Pin,
                _ => CertificateDecision::Reject,
            };
            control.certificate_reply(prompt.prompt_id, decision)
        }
        ConnectEvent::Browser(prompt) => {
            say(&format!(
                "Browser authentication: {} ({:?})",
                prompt.expected_origin, prompt.phase
            ))?;
            match prompt.stage {
                BrowserStage::ManualInput => {
                    let url = control.browser_manual_url(prompt.transaction_id)?;
                    say(
                        "Open this private URL. Custom-scheme OS dispatch may expose its callback in process arguments; never share it.",
                    )?;
                    say(url.as_str())?;
                    let callback =
                        input("Paste callback (hidden)", true, &stop, MAX_BROWSER_BYTES)?;
                    control.browser_callback(prompt.transaction_id, SecretText(callback))
                }
                BrowserStage::ConfirmAccount => {
                    let answer = line(
                        &format!(
                            "Continue as {} at {}? [yes/no]",
                            prompt.account.as_deref().unwrap_or("unknown account"),
                            prompt.expected_origin
                        ),
                        false,
                        &stop,
                    )?;
                    control.browser_confirm(prompt.transaction_id, answer.as_str() == "yes")
                }
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}
