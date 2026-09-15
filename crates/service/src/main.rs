use clap::{Parser, Subcommand};
use ocvpn_model::{Error, ErrorCode, Result};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "ocvpnd",
    version,
    about = "OpenConnect GUI privileged tunnel service",
    args_conflicts_with_subcommands = true
)]
struct Arguments {
    #[arg(long, hide = true, conflicts_with = "foreground")]
    worker: bool,
    #[arg(long)]
    foreground: bool,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    Endpoint,
    CheckEndpoint,
}
fn main() -> ExitCode {
    let arguments = Arguments::parse();
    #[cfg(windows)]
    if !arguments.worker && !arguments.foreground && arguments.command.is_none() {
        return finish(ocvpn_service::scm::dispatch());
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            return finish(Err(Error::new(
                ErrorCode::RuntimeFailure,
                "Cannot initialize service runtime",
            )));
        }
    };
    let result = runtime.block_on(async move {
        if arguments.worker {
            return ocvpn_service::worker::run().await;
        }
        match arguments.command {
            Some(Command::Endpoint) => {
                println!("{}", ocvpn_service::CONTROL_ENDPOINT);
                Ok(())
            }
            Some(Command::CheckEndpoint) => {
                #[cfg(unix)]
                let result = ocvpn_service::unix::connect_control().await.map(drop);
                #[cfg(windows)]
                let result = ocvpn_service::windows::connect_control().map(drop);
                result.map_err(|_| {
                    Error::new(
                        ErrorCode::ServiceUnavailable,
                        "Control endpoint unavailable or untrusted",
                    )
                })?;
                println!("Endpoint peer identity verified; use ocvpn status for tunnel state.");
                Ok(())
            }
            None => {
                let (stop, stopped) = tokio::sync::watch::channel(false);
                let signals = tokio::spawn(async move {
                    #[cfg(unix)]
                    {
                        let mut term = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate(),
                        )
                        .map_err(|_| {
                            Error::new(
                                ErrorCode::RuntimeFailure,
                                "Cannot register termination signal",
                            )
                        })?;
                        tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
                    }
                    #[cfg(windows)]
                    {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                    let _ = stop.send(true);
                    Ok::<(), Error>(())
                });
                let result = ocvpn_service::daemon::run(stopped).await;
                signals.abort();
                let _ = signals.await;
                result
            }
        }
    });
    // Tokio's stdin adapter can retain a blocking read after its async task is
    // cancelled. Do not deadlock worker exit against the parent's retained pipe.
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    finish(result)
}
fn finish(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.message);
            ExitCode::from(error.exit_code())
        }
    }
}
