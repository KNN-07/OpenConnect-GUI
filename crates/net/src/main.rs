use std::{
    io::{self, Read},
    process::ExitCode,
};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let arg = args.next();
    if args.next().is_some() {
        eprintln!("ocvpn-net: expected --validate-stdin or --version");
        return ExitCode::from(2);
    }
    match arg.as_deref().and_then(|s| s.to_str()) {
        Some("--version") => {
            println!("ocvpn-net {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--validate-stdin") => {
            let mut input = Vec::new();
            if io::stdin()
                .lock()
                .take((ocvpn_net::MAX_INPUT_BYTES + 1) as u64)
                .read_to_end(&mut input)
                .is_err()
            {
                eprintln!("ocvpn-net: could not read configuration input");
                return ExitCode::from(2);
            }
            match ocvpn_net::validate_json(&input) {
                Ok(_) => {
                    println!("Configuration valid; no network changes performed.");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ocvpn-net: {error}");
                    ExitCode::from(2)
                }
            }
        }
        None if arg.is_none() => {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => return ExitCode::FAILURE,
            };
            match runtime.block_on(ocvpn_net::monitor::run_helper()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("ocvpn-net: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("ocvpn-net: expected no arguments, --validate-stdin or --version");
            ExitCode::from(2)
        }
    }
}
