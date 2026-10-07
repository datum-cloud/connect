use std::{
    ffi::c_void,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicPtr, Ordering},
    },
};

use tokio_util::sync::CancellationToken;
use windows::{
    Win32::{
        Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR},
        System::{
            EventLog::{
                DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
            },
            Services::{
                RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
                SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
                SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
                SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
                StartServiceCtrlDispatcherW,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::{Args, run};
use datum_connect_daemon::error::ApiError;

const SERVICE_NAME: &[u16] = &[
    b'd' as u16,
    b'a' as u16,
    b't' as u16,
    b'u' as u16,
    b'm' as u16,
    b'-' as u16,
    b'c' as u16,
    b'o' as u16,
    b'n' as u16,
    b'n' as u16,
    b'e' as u16,
    b'c' as u16,
    b't' as u16,
    b'-' as u16,
    b'd' as u16,
    b'a' as u16,
    b'e' as u16,
    b'm' as u16,
    b'o' as u16,
    b'n' as u16,
    0,
];

static ARGS: OnceLock<Args> = OnceLock::new();
static SHUTDOWN: OnceLock<CancellationToken> = OnceLock::new();
static STATUS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
// Serialize callbacks with readiness. A stale readiness callback must never
// turn STOP_PENDING back into RUNNING after SCM has requested a stop.
static PHASE: Mutex<u32> = Mutex::new(0);

pub(super) fn dispatch(args: Args) -> Result<(), ApiError> {
    ARGS.set(args)
        .map_err(|_| ApiError::internal("Windows service arguments were already initialized"))?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(SERVICE_NAME.as_ptr().cast_mut()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|error| {
        event_log_error("service dispatcher startup", Some(error.code().0 as u32));
        ApiError::internal(format!("starting Windows service dispatcher: {error}"))
    })
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let shutdown = CancellationToken::new();
    let _ = SHUTDOWN.set(shutdown.clone());
    let handle = match unsafe {
        RegisterServiceCtrlHandlerExW(PCWSTR(SERVICE_NAME.as_ptr()), Some(control_handler), None)
    } {
        Ok(handle) => handle,
        Err(error) => {
            event_log_error(
                "service control handler registration",
                Some(error.code().0 as u32),
            );
            tracing::error!(%error, "registering Windows service control handler failed");
            return;
        }
    };
    STATUS.store(handle.0, Ordering::Release);
    report(SERVICE_START_PENDING, 0, 10_000);

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            event_log_error("async runtime initialization", error.raw_os_error().map(|v| v as u32));
            eprintln!("failed to create Windows service runtime: {error}");
            ApiError::internal(format!("creating Windows service runtime: {error}"))
        })
        .and_then(|runtime| {
            let result = runtime.block_on(async {
                let args = ARGS.get().expect("service args initialized").clone();
                let _log_guard = match super::init_tracing(args.log_file.as_deref()).await {
                    Ok(guard) => guard,
                    Err(error) => {
                        event_log_error(
                            "protected logging initialization",
                            error.raw_os_error().map(|value| value as u32),
                        );
                        eprintln!("failed to initialize Windows service logging: {error}");
                        return Err(ApiError::internal(format!(
                            "initializing Windows service logging: {error}"
                        )));
                    }
                };
                let result = run(args, Some(shutdown), Some(report_running)).await;
                if let Err(error) = &result {
                    tracing::error!(stage = "windows_service", error = %error, "daemon_service_failed");
                    event_log_error("daemon runtime; inspect the protected daemon log", None);
                }
                result
            });
            runtime.shutdown_timeout(std::time::Duration::from_secs(2));
            result
        });
    match result {
        Ok(()) => report(SERVICE_STOPPED, 0, 0),
        Err(_) => report_error(),
    }
}

/// Last-resort diagnostics for failures before protected file logging exists,
/// or after SCM has detached standard error. Messages contain only a static
/// lifecycle stage and an optional OS status code; never request or credential
/// content. The installer registers this source with Windows Event Log.
fn event_log_error(stage: &'static str, os_code: Option<u32>) {
    let source = SERVICE_NAME;
    let message = match os_code {
        Some(code) => format!("Datum Connect daemon failure during {stage} (OS status {code})."),
        None => format!("Datum Connect daemon failure during {stage}."),
    };
    let message: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let Ok(handle) = (unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(source.as_ptr())) })
    else {
        return;
    };
    let strings = [PCWSTR(message.as_ptr())];
    let _ = unsafe {
        ReportEventW(
            handle,
            EVENTLOG_ERROR_TYPE,
            0,
            1,
            None,
            0,
            Some(&strings),
            None,
        )
    };
    let _ = unsafe { DeregisterEventSource(handle) };
}

fn report_running() {
    if !SHUTDOWN.get().is_some_and(CancellationToken::is_cancelled) {
        report(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0,
        );
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    if is_stop_control(control) {
        report(SERVICE_STOP_PENDING, 0, 35_000);
        if let Some(shutdown) = SHUTDOWN.get() {
            shutdown.cancel();
        }
    }
    NO_ERROR.0
}

fn is_stop_control(control: u32) -> bool {
    control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN
}

fn report(
    state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    accepted: u32,
    wait_hint: u32,
) {
    let mut phase = PHASE.lock().unwrap_or_else(|error| error.into_inner());
    if !may_transition(*phase, state.0) {
        return;
    }
    *phase = state.0;
    let handle = SERVICE_STATUS_HANDLE(STATUS.load(Ordering::Acquire));
    if handle.is_invalid() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: NO_ERROR.0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: u32::from(state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING),
        dwWaitHint: wait_hint,
    };
    if let Err(error) = unsafe { SetServiceStatus(handle, &status) } {
        tracing::error!(%error, "reporting Windows service status failed");
    }
}

fn report_error() {
    let mut phase = PHASE.lock().unwrap_or_else(|error| error.into_inner());
    *phase = SERVICE_STOPPED.0;
    let handle = SERVICE_STATUS_HANDLE(STATUS.load(Ordering::Acquire));
    if handle.is_invalid() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_STOPPED,
        dwControlsAccepted: 0,
        dwWin32ExitCode: ERROR_SERVICE_SPECIFIC_ERROR.0,
        dwServiceSpecificExitCode: 1,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    let _ = unsafe { SetServiceStatus(handle, &status) };
}

fn may_transition(current: u32, requested: u32) -> bool {
    match current {
        0 => requested == SERVICE_START_PENDING.0,
        value if value == SERVICE_START_PENDING.0 => {
            requested == SERVICE_RUNNING.0
                || requested == SERVICE_STOP_PENDING.0
                || requested == SERVICE_STOPPED.0
        }
        value if value == SERVICE_RUNNING.0 => {
            requested == SERVICE_STOP_PENDING.0 || requested == SERVICE_STOPPED.0
        }
        value if value == SERVICE_STOP_PENDING.0 => {
            requested == SERVICE_STOP_PENDING.0 || requested == SERVICE_STOPPED.0
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn late_readiness_cannot_undo_stop() {
        assert!(may_transition(0, SERVICE_START_PENDING.0));
        assert!(!may_transition(0, SERVICE_RUNNING.0));
        assert!(!may_transition(0, SERVICE_STOP_PENDING.0));
        assert!(may_transition(SERVICE_START_PENDING.0, SERVICE_RUNNING.0));
        assert!(may_transition(SERVICE_RUNNING.0, SERVICE_STOP_PENDING.0));
        assert!(!may_transition(SERVICE_STOP_PENDING.0, SERVICE_RUNNING.0));
        assert!(!may_transition(
            SERVICE_STOP_PENDING.0,
            SERVICE_START_PENDING.0
        ));
        assert!(may_transition(SERVICE_STOP_PENDING.0, SERVICE_STOPPED.0));
        assert!(!may_transition(SERVICE_STOPPED.0, SERVICE_RUNNING.0));
        assert!(!may_transition(SERVICE_RUNNING.0, SERVICE_START_PENDING.0));
    }

    #[test]
    fn stop_and_system_shutdown_share_bounded_cancellation_path() {
        assert!(is_stop_control(SERVICE_CONTROL_STOP));
        assert!(is_stop_control(SERVICE_CONTROL_SHUTDOWN));
        assert!(!is_stop_control(0));
    }
}
