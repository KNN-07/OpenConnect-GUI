//! Minimal OS protocol receiver. Custom-URL dispatch may expose argv to the OS;
//! never print it or construct another URL-bearing command line.
#![cfg_attr(windows, windows_subsystem = "windows")]
use ocvpn_model::{Error, ErrorCode, Result, SecretText};
fn receive() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let input = arguments.next();
    #[cfg(target_os = "macos")]
    if input.is_none() {
        return ocvpn_client::browser_os::run_callback_receiver();
    }
    let input = input.ok_or_else(|| Error::invalid("An OS authentication callback is required"))?;
    let uri = SecretText::new(
        input
            .into_string()
            .map_err(|_| Error::invalid("Invalid authentication callback encoding"))?,
    );
    if arguments.next().is_some() {
        return Err(Error::invalid(
            "Only one authentication callback is accepted",
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| {
            Error::new(
                ErrorCode::RuntimeFailure,
                "Callback forwarding is unavailable",
            )
        })?;
    runtime.block_on(ocvpn_client::browser::submit_callback(uri))
}
fn main() {
    if let Err(error) = receive() {
        std::process::exit(i32::from(error.exit_code()));
    }
}
