//! Native SCM dispatcher; no GUI or user authentication runs in session zero.
use ocvpn_model::{Error, ErrorCode, Result};
use std::{
    ffi::OsString,
    sync::{Arc, Mutex},
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};
const NAME: &str = "OpenConnectGUI";
define_windows_service!(ffi_service_main, service_main);
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(NAME, ffi_service_main)
        .map_err(|_| failure("Cannot attach to Windows Service Control Manager"))
}
fn failure(message: &str) -> Error {
    Error::new(ErrorCode::ServiceUnavailable, message)
}
fn status(
    handle: ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
    exit: u32,
) -> Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint,
            wait_hint: if matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            ) {
                Duration::from_secs(30)
            } else {
                Duration::ZERO
            },
            process_id: None,
        })
        .map_err(|_| failure("Cannot report Windows service state"))
}
fn service_main(_: Vec<OsString>) {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let shared = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
    let phase = Arc::new(Mutex::new(ServiceState::StartPending));
    let control_phase = phase.clone();
    let control_status = shared.clone();
    let registration = service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let mut phase = control_phase.lock().unwrap_or_else(|e| e.into_inner());
            *phase = ServiceState::StopPending;
            if let Some(handle) = *control_status.lock().unwrap_or_else(|e| e.into_inner()) {
                let _ = status(handle, *phase, 1, 0);
            }
            let _ = stop.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    });
    let Ok(handle) = registration else {
        return;
    };
    *shared.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    if status(handle, ServiceState::StartPending, 1, 0).is_err() {
        return;
    }
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| failure("Cannot create service runtime"))
        .and_then(|runtime| {
            runtime.block_on(async {
                let heartbeat_phase = phase.clone();
                let heartbeat = tokio::spawn(async move {
                    let mut checkpoint = 1;
                    loop {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        let phase = heartbeat_phase.lock().unwrap_or_else(|e| e.into_inner());
                        if matches!(
                            *phase,
                            ServiceState::StartPending | ServiceState::StopPending
                        ) {
                            checkpoint += 1;
                            if status(handle, *phase, checkpoint, 0).is_err() {
                                break;
                            }
                        }
                    }
                });
                let result = crate::daemon::run_with_ready(stopped, || {
                    let mut phase = phase.lock().unwrap_or_else(|e| e.into_inner());
                    if *phase != ServiceState::StopPending {
                        *phase = ServiceState::Running;
                        status(handle, *phase, 0, 0)?;
                    }
                    Ok(())
                })
                .await;
                heartbeat.abort();
                let _ = heartbeat.await;
                result
            })
        });
    let _ = status(
        handle,
        ServiceState::Stopped,
        0,
        if result.is_ok() { 0 } else { 1 },
    );
}
