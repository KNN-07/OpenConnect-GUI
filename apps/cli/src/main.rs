mod terminal;
mod tui;
use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};
use ocvpn_client::{
    auth::AuthInputs,
    connect::{self, ConnectEvent},
    daemon,
    profiles::ProfileStore,
    save_settings,
};
use ocvpn_model::*;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    ffi::OsString,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "ocvpn", version, about = "OpenConnect GUI command-line client")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Protocols,
    Doctor,
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    Connect {
        selector: String,
        #[arg(long)]
        foreground: bool,
        #[arg(long)]
        non_interactive: bool,
        #[arg(long, conflicts_with = "cookie_stdin")]
        password_stdin: bool,
        #[arg(long)]
        cookie_stdin: bool,
        #[arg(long, value_parser=["auto","system","embedded","manual"])]
        browser: Option<String>,
    },
    Disconnect,
    Status {
        #[arg(long)]
        watch: bool,
    },
    Logs {
        #[arg(long)]
        follow: bool,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    Autoconnect,
    Tui,
    Gui,
    Completions {
        shell: clap_complete::Shell,
    },
}
#[derive(Subcommand)]
enum ProfileCommand {
    List,
    Show {
        selector: String,
    },
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    Update {
        selector: String,
        #[arg(long)]
        file: PathBuf,
    },
    Duplicate {
        selector: String,
        #[arg(long)]
        name: String,
    },
    Remove {
        selector: String,
        #[arg(long)]
        yes: bool,
    },
    Import {
        file: PathBuf,
    },
    Export {
        selector: Option<String>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
}
#[derive(Subcommand)]
enum SettingsCommand {
    Show,
    Set { key: String, value: String },
}
#[derive(Subcommand)]
enum ServiceCommand {
    Install,
    Uninstall,
    Status,
    Repair,
}
#[derive(Serialize)]
struct Success<T> {
    schema_version: u32,
    data: T,
}
#[derive(Serialize)]
struct Failure<'a> {
    schema_version: u32,
    error: &'a Error,
}
fn runtime_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::RuntimeFailure, message)
}
fn interrupted() -> Error {
    Error::new(ErrorCode::Cancelled, "Interrupted")
}
fn terminal_text(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}
fn output(value: &impl Serialize, json: bool) -> Result<()> {
    let mut out = io::stdout().lock();
    if json {
        serde_json::to_writer(
            &mut out,
            &Success {
                schema_version: 1,
                data: value,
            },
        )
    } else {
        serde_json::to_writer_pretty(&mut out, value)
    }
    .map_err(|_| runtime_error("Unable to encode output"))?;
    writeln!(out)
        .and_then(|()| out.flush())
        .map_err(|_| runtime_error("Unable to write command output"))
}
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| runtime_error("Client worker stopped unexpectedly"))?
}
async fn store<T: Send + 'static>(
    work: impl FnOnce(ProfileStore) -> Result<T> + Send + 'static,
) -> Result<T> {
    blocking(move || work(ProfileStore::open()?)).await
}
fn read_file(path: &std::path::Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|_| Error::invalid("Cannot open input file"))?;
    let mut bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::invalid("Cannot read input file"))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(Error::invalid("Input file exceeds 8 MiB"));
    }
    Ok(bytes)
}
async fn confirm(text: String) -> Result<bool> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let owned = stop.clone();
    let mut task = tokio::task::spawn_blocking(move || terminal::confirm(&text, &owned));
    tokio::select! {
    result=&mut task=>result.map_err(|_|runtime_error("Terminal confirmation failed"))?,
    signal=interruption()=>{stop.store(true,std::sync::atomic::Ordering::Release);let _=tokio::time::timeout(std::time::Duration::from_secs(1),&mut task).await;Err(signal.err().unwrap_or_else(interrupted))}
    }
}
async fn primary_password() -> Result<Option<Zeroizing<String>>> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let owned = stop.clone();
    let mut task = tokio::task::spawn_blocking(move || terminal::primary_password(&owned));
    tokio::select! {
    result=&mut task=>{let value=result.map_err(|_|runtime_error("Private password input failed"))??;Ok(if value.is_empty(){None}else{Some(value)})},
    signal=interruption()=>{stop.store(true,std::sync::atomic::Ordering::Release);let _=tokio::time::timeout(std::time::Duration::from_secs(1),&mut task).await;Err(signal.err().unwrap_or_else(interrupted))}
    }
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| Error::invalid("Invalid JSON document or fields"))
}
fn secret_stdin() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::invalid("Cannot read private stdin"))?;
    if bytes.len() > 65536 {
        return Err(Error::invalid("Secret stdin exceeds 64 KiB"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::invalid("Secret stdin must be UTF-8"))?;
    Ok(Zeroizing::new(
        text.trim_end_matches(['\r', '\n']).to_owned(),
    ))
}
async fn disconnect_wait() -> Result<()> {
    daemon::disconnect().await?;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let snapshot = daemon::snapshot().await?;
            if matches!(
                snapshot.state,
                ConnectionState::Disconnected
                    | ConnectionState::Failed
                    | ConnectionState::AuthenticationRequired
            ) {
                if snapshot.last_error.as_ref().is_some_and(|e| {
                    matches!(
                        e.code,
                        ErrorCode::RecoveryRequired | ErrorCode::NetworkFailure
                    )
                }) {
                    return Err(snapshot.last_error.unwrap());
                }
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| {
        runtime_error("Disconnect cleanup is still pending; run ocvpn doctor before retrying")
    })?
}
async fn remove_profile(profile: Profile) -> Result<()> {
    ocvpn_client::remove_profile(profile.id, profile.revision).await
}
async fn run(cli: Cli) -> Result<u8> {
    let json = cli.json;
    let result: Result<()> = match cli.command {
        Command::Protocols => output(&blocking(ocvpn_client::capabilities).await?, json),
        Command::Doctor => {
            let report = ocvpn_client::installation::doctor().await;
            let exit = report
                .engine_error
                .as_ref()
                .or(report.service_error.as_ref())
                .or(report.driver_error.as_ref())
                .map_or_else(
                    || {
                        if report.driver_ready && report.service.as_ref().is_some_and(|s| s.running)
                        {
                            0
                        } else {
                            1
                        }
                    },
                    Error::exit_code,
                );
            output(&report, json)?;
            return Ok(exit);
        }
        Command::Profile { command } => match command {
            ProfileCommand::List => output(&store(|s| s.list()).await?, json),
            ProfileCommand::Show { selector } => {
                output(&store(move |s| s.resolve(&selector)).await?, json)
            }
            ProfileCommand::Add {
                name,
                server,
                protocol,
                file,
            } => output(
                &store(move |s| {
                    let mut value = serde_json::to_value(Profile::new(
                        name.clone(),
                        parse_server(&server)?,
                        protocol.clone(),
                    ))
                    .map_err(|_| runtime_error("Cannot encode profile"))?;
                    if let Some(path) = file {
                        let advanced: serde_json::Map<String, serde_json::Value> =
                            decode(&read_file(&path)?)?;
                        for (key, item) in advanced {
                            value[&key] = item;
                        }
                    }
                    value["name"] = serde_json::Value::String(name);
                    value["server"] = serde_json::Value::String(parse_server(&server)?.to_string());
                    value["protocol"] = serde_json::Value::String(protocol);
                    let profile: Profile = serde_json::from_value(value)
                        .map_err(|_| Error::invalid("Invalid advanced profile metadata"))?;
                    s.create(profile)
                })
                .await?,
                json,
            ),
            ProfileCommand::Update { selector, file } => output(
                &store(move |s| {
                    let old = s.resolve(&selector)?;
                    let p: Profile = decode(&read_file(&file)?)?;
                    if p.id != old.id {
                        return Err(Error::invalid(
                            "Edited profile ID differs from selected profile",
                        ));
                    }
                    s.update(p)
                })
                .await?,
                json,
            ),
            ProfileCommand::Duplicate { selector, name } => {
                output(&store(move |s| s.duplicate(&selector, &name)).await?, json)
            }
            ProfileCommand::Remove { selector, yes } => {
                let p = store(move |s| s.resolve(&selector)).await?;
                if !yes {
                    if !confirm(format!("Remove {} and its saved credentials?", p.name)).await? {
                        return Err(interrupted());
                    }
                }
                remove_profile(p).await?;
                output(&"removed", json)
            }
            ProfileCommand::Import { file } => output(
                &store(move |s| s.import_json(&read_file(&file)?)).await?,
                json,
            ),
            ProfileCommand::Export {
                selector,
                output: path,
                force,
            } => {
                store(move |s| s.export_file(selector.as_deref(), &path, force)).await?;
                output(&"exported", json)
            }
        },
        Command::Settings { command } => match command {
            SettingsCommand::Show => output(&blocking(ocvpn_client::settings_read).await?, json),
            SettingsCommand::Set { key, value } => {
                let mut doc = store(|s| s.settings()).await?;
                match key.as_str() {
                    "theme" => doc.settings.theme = decode(format!("\"{value}\"").as_bytes())?,
                    "start_at_login" => {
                        doc.settings.start_at_login = value
                            .parse()
                            .map_err(|_| Error::invalid("Expected true or false"))?
                    }
                    "close_to_tray" => {
                        doc.settings.close_to_tray = value
                            .parse()
                            .map_err(|_| Error::invalid("Expected true or false"))?
                    }
                    "auto_connect_profile_id" => {
                        doc.settings.auto_connect_profile_id = if value == "none" || value == "null"
                        {
                            None
                        } else {
                            Some(store(move |s| s.resolve(&value)).await?.id)
                        }
                    }
                    _ => return Err(Error::invalid("Unknown settings key")),
                };
                output(&save_settings(doc.settings, doc.revision).await?, json)
            }
        },
        Command::Connect {
            selector,
            foreground,
            non_interactive,
            password_stdin,
            cookie_stdin,
            browser,
        } => {
            let mut p = store(move |s| s.resolve(&selector)).await?;
            if let Some(mode) = browser {
                p.browser_mode = decode(format!("\"{mode}\"").as_bytes())?;
            }
            let mut inputs = AuthInputs {
                non_interactive,
                ..Default::default()
            };
            let mut handoff = None;
            if password_stdin {
                inputs.password = Some(blocking(secret_stdin).await?);
            }
            if cookie_stdin {
                handoff =
                    Some(blocking(|| decode::<AuthHandoff>(secret_stdin()?.as_bytes())).await?);
            }
            if p.remember_password && !non_interactive && !password_stdin && !cookie_stdin {
                let snapshot = daemon::snapshot().await?;
                if !matches!(
                    snapshot.state,
                    ConnectionState::Disconnected
                        | ConnectionState::Failed
                        | ConnectionState::AuthenticationRequired
                ) {
                    return Err(Error::new(
                        ErrorCode::Busy,
                        "A connection is active or pending",
                    ));
                }
                inputs.password = primary_password().await?;
            }
            connect_cli(p, inputs, handoff, foreground, json).await
        }
        Command::Disconnect => {
            disconnect_wait().await?;
            output(&daemon::snapshot().await?, json)
        }
        Command::Status { watch: false } => output(&daemon::snapshot().await?, json),
        Command::Status { watch: true } => follow(false, false, json).await,
        Command::Logs { follow: false } => {
            let value = daemon::Connection::open()
                .await?
                .call(ipc::Method::Logs { follow: false })
                .await?;
            output(&value, json)
        }
        Command::Logs { follow: true } => follow(true, false, json).await,
        Command::Service { command } => {
            let status = match command {
                ServiceCommand::Status => ocvpn_client::installation::status().await?,
                ServiceCommand::Install => {
                    ocvpn_client::installation::manage(ServiceAction::Install).await?
                }
                ServiceCommand::Uninstall => {
                    ocvpn_client::installation::manage(ServiceAction::Uninstall).await?
                }
                ServiceCommand::Repair => {
                    ocvpn_client::installation::manage(ServiceAction::Repair).await?
                }
            };
            output(&status, json)
        }
        Command::Autoconnect => {
            let read = blocking(ocvpn_client::settings_read).await?;
            if let Some(e) = read.auto_connect_error {
                return Err(e);
            }
            let Some(id) = read.document.settings.auto_connect_profile_id else {
                return output(&"auto-connect disabled", json).map(|()| 0);
            };
            let snapshot = daemon::snapshot().await?;
            if snapshot.profile_id == Some(id)
                && matches!(
                    snapshot.state,
                    ConnectionState::Connected | ConnectionState::Reconnecting
                )
            {
                return output(&snapshot, json).map(|()| 0);
            }
            if !matches!(
                snapshot.state,
                ConnectionState::Disconnected
                    | ConnectionState::Failed
                    | ConnectionState::AuthenticationRequired
            ) {
                return Err(Error::new(
                    ErrorCode::Busy,
                    "Another connection is active or pending",
                ));
            }
            let p = store(move |s| s.resolve(&id.to_string())).await?;
            connect_cli(
                p,
                AuthInputs {
                    non_interactive: true,
                    ..Default::default()
                },
                None,
                false,
                json,
            )
            .await
        }
        Command::Gui => ocvpn_client::installation::launch_gui().await,
        Command::Tui => {
            if json {
                return Err(Error::invalid("The full-screen TUI cannot emit JSON"));
            }
            tui::run().await
        }
        Command::Completions { shell } => {
            if json {
                let mut bytes = Vec::new();
                clap_complete::generate(shell, &mut Cli::command(), "ocvpn", &mut bytes);
                output(&String::from_utf8_lossy(&bytes), true)
            } else {
                clap_complete::generate(shell, &mut Cli::command(), "ocvpn", &mut io::stdout());
                Ok(())
            }
        }
    };
    result?;
    Ok(0)
}
async fn connect_cli(
    profile: Profile,
    inputs: AuthInputs,
    handoff: Option<AuthHandoff>,
    foreground: bool,
    json: bool,
) -> Result<()> {
    let noninteractive = inputs.non_interactive;
    let mut attempt = connect::start(profile, inputs, handoff)?;
    let control = attempt.control();
    let mut pending = std::collections::VecDeque::new();
    let result=async {loop {tokio::select! {
 signal=interruption()=>return Err(signal.err().unwrap_or_else(interrupted)),
 event=async{if let Some(event)=pending.pop_front(){Some(event)}else{attempt.next().await}}=>match event {
 Some(ConnectEvent::Connected(snapshot))=>{output(&snapshot,json)?;return Ok(());},
 Some(ConnectEvent::Failed(error))=>return Err(error),Some(ConnectEvent::Cancelled)|None=>return Err(interrupted()),
 Some(event @ (ConnectEvent::Prompt(_)|ConnectEvent::Certificate(_)|ConnectEvent::Browser(_)))=>{
 if noninteractive {return Err(Error::new(ErrorCode::AuthenticationRequired,"Connect interactively to complete authentication"));}
 let owned=control.clone();let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));let input_stop=stop.clone();let mut interaction=tokio::task::spawn_blocking(move||terminal::interaction(event,owned,input_stop));
 loop {tokio::select!{
 signal=interruption()=>{stop.store(true,std::sync::atomic::Ordering::Release);control.cancel();let _=tokio::time::timeout(std::time::Duration::from_secs(1),&mut interaction).await;return Err(signal.err().unwrap_or_else(interrupted));},
 result=&mut interaction=>{result.map_err(|_|runtime_error("Authentication input worker failed"))??;break;},
 event=attempt.next()=>match event {
  Some(ConnectEvent::Failed(error))=>{stop.store(true,std::sync::atomic::Ordering::Release);let _=tokio::time::timeout(std::time::Duration::from_secs(1),&mut interaction).await;return Err(error);},
  Some(ConnectEvent::Cancelled)|None=>{stop.store(true,std::sync::atomic::Ordering::Release);let _=tokio::time::timeout(std::time::Duration::from_secs(1),&mut interaction).await;return Err(interrupted());},
  Some(ConnectEvent::Connected(snapshot))=>{stop.store(true,std::sync::atomic::Ordering::Release);let _=tokio::time::timeout(std::time::Duration::from_secs(1),&mut interaction).await;output(&snapshot,json)?;return Ok(());},
  Some(event @ (ConnectEvent::Prompt(_)|ConnectEvent::Certificate(_)|ConnectEvent::Browser(_)))=>{stop.store(true,std::sync::atomic::Ordering::Release);let _=tokio::time::timeout(std::time::Duration::from_secs(1),&mut interaction).await;pending.push_back(event);break;},
  Some(event)=>pending.push_back(event),
 }
 }}
 },
 Some(ConnectEvent::Notice(error))=>{let _=writeln!(io::stderr(),"{}",terminal_text(&error.message));},_=>{},
 }
 }}}.await;
    if result.is_err() {
        control.cancel();
        while let Some(event) = attempt.next().await {
            if let ConnectEvent::Failed(error) = event {
                if matches!(
                    error.code,
                    ErrorCode::ServiceUnavailable
                        | ErrorCode::RecoveryRequired
                        | ErrorCode::NetworkFailure
                ) {
                    return Err(error);
                }
            }
        }
    }
    result?;
    if foreground {
        follow(false, true, json).await
    } else {
        Ok(())
    }
}
async fn follow(logs: bool, foreground: bool, json: bool) -> Result<()> {
    let connection = daemon::Connection::open().await?;
    let mut events = if logs {
        connection.follow_logs().await?
    } else {
        connection.subscribe().await?
    };
    for record in events.take_backlog() {
        output(&record, json)?;
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let reader = tokio::spawn(async move {
        loop {
            let event = events.next().await;
            let failed = event.is_err();
            if tx.send(event).await.is_err() || failed {
                break;
            }
        }
    });
    let result=async {loop{tokio::select!{
 signal=interruption()=>{if foreground{disconnect_wait().await?;}return Err(signal.err().unwrap_or_else(interrupted));},
 event=rx.recv()=>{let event=event.ok_or_else(||runtime_error("Service event stream ended"))??;output(&event,json)?;if foreground {if let ipc::EventPayload::Snapshot(s)=event.payload {if matches!(s.state,ConnectionState::Disconnected){return Ok(());}if matches!(s.state,ConnectionState::Failed|ConnectionState::AuthenticationRequired){return Err(s.last_error.unwrap_or_else(||runtime_error("Tunnel ended")));}}}},
 }}}.await;
    reader.abort();
    result
}
async fn interruption() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())
            .map_err(|_| runtime_error("Cannot observe termination signals"))?;
        let mut hangup = signal(SignalKind::hangup())
            .map_err(|_| runtime_error("Cannot observe terminal closure"))?;
        tokio::select! {result=tokio::signal::ctrl_c()=>result.map_err(|_|runtime_error("Cannot observe interrupt signals")),_=terminate.recv()=>Ok(()),_=hangup.recv()=>Ok(())}
    }
    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| runtime_error("Cannot observe interrupt signals"))
    }
}
fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let json = args
        .iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .any(|a| a == "--json");
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                if json {
                    if let Err(error) = output(&e.to_string(), true) {
                        return report(&error, true);
                    }
                } else {
                    let _ = e.print();
                }
                return ExitCode::SUCCESS;
            }
            return report(&Error::invalid(e.to_string()), json);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return report(&runtime_error("Cannot create client runtime"), json),
    };
    let result = runtime.block_on(run(cli));
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => report(&e, json),
    }
}
fn report(error: &Error, json: bool) -> ExitCode {
    if json {
        let mut out = io::stdout().lock();
        let _ = serde_json::to_writer(
            &mut out,
            &Failure {
                schema_version: 1,
                error,
            },
        );
        let _ = writeln!(out);
    } else {
        let _ = writeln!(io::stderr(), "Error: {}", terminal_text(&error.message));
        if let Some(details) = &error.details {
            let _ = writeln!(io::stderr(), "{}", terminal_text(details));
        }
    }
    ExitCode::from(error.exit_code())
}
