use clap::Parser;
use ocvpn_service::installation::{InstallerCommand, execute};
use std::process::ExitCode;
#[derive(Parser)]
#[command(
    name = "ocvpn-installer",
    version,
    about = "Fixed native OpenConnect GUI service manager"
)]
struct Arguments {
    #[arg(value_enum)]
    command: InstallerCommand,
}
fn main() -> ExitCode {
    match execute(Arguments::parse().command) {
        Ok(status) => match serde_json::to_writer(std::io::stdout().lock(), &status) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        },
        Err(error) => {
            let _ = serde_json::to_writer(std::io::stderr().lock(), &error);
            ExitCode::from(error.exit_code())
        }
    }
}
