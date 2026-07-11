// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("axis-wfp-broker is available only on Windows");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
fn main() {
    if let Err(error) = windows_main() {
        eprintln!("axis-wfp-broker: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn windows_main() -> Result<(), String> {
    use axis_sandbox::windows::wfp::{BrokerConfig, serve};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let mut args = std::env::args_os();
    let _program = args.next();
    let command = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "run".into());
    if args.next().is_some() {
        return Err("usage: axis-wfp-broker [run|service|probe]".into());
    }

    match command.as_str() {
        "run" => serve(BrokerConfig::default(), Arc::new(AtomicBool::new(false))),
        "service" => service::dispatch(),
        "probe" => probe(),
        _ => Err("usage: axis-wfp-broker [run|service|probe]".into()),
    }
}

#[cfg(target_os = "windows")]
fn probe() -> Result<(), String> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FwpmEngineClose0, FwpmEngineOpen0,
    };
    use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
    use windows::core::PCWSTR;

    let mut engine = HANDLE::default();
    let session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        txnWaitTimeoutInMSec: 1_000,
        ..Default::default()
    };
    let status = unsafe {
        FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            Some(&session),
            &mut engine,
        )
    };
    if status != 0 {
        return Err(format!(
            "Windows Filtering Platform engine unavailable: 0x{status:08X}"
        ));
    }
    unsafe {
        let _ = FwpmEngineClose0(engine);
    }
    println!("AXIS_WFP_BROKER_PROBE_OK");
    Ok(())
}

#[cfg(target_os = "windows")]
mod service {
    use axis_sandbox::windows::wfp::{BrokerConfig, DEFAULT_PIPE_NAME, serve};
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
        SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
        StartServiceCtrlDispatcherW,
    };
    use windows::core::{PWSTR, w};

    const SERVICE_NAME: windows::core::PCWSTR = w!("AxisWfpBroker");
    static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    static STATUS: OnceLock<usize> = OnceLock::new();

    pub(super) fn dispatch() -> Result<(), String> {
        let mut name = "AxisWfpBroker\0".encode_utf16().collect::<Vec<_>>();
        let entries = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) }
            .map_err(|e| format!("StartServiceCtrlDispatcherW failed: {e}"))
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
        let handle = match unsafe {
            RegisterServiceCtrlHandlerExW(SERVICE_NAME, Some(control_handler), None)
        } {
            Ok(handle) => handle,
            Err(_) => return,
        };
        let _ = STATUS.set(handle.0 as usize);
        report(SERVICE_START_PENDING, 0, 10_000);

        let stop = Arc::new(AtomicBool::new(false));
        let _ = STOP.set(stop.clone());
        report(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0,
        );
        let exit_code = match serve(BrokerConfig::default(), stop) {
            Ok(()) => 0,
            Err(_) => 1,
        };
        report(SERVICE_STOPPED, 0, 0);
        if exit_code != 0 {
            // SCM observes the nonzero service-specific result in the final
            // status reported below on a future extension; for now the broker
            // audit log carries the actionable error without exposing secrets.
        }
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            report(SERVICE_STOP_PENDING, 0, 5_000);
            if let Some(stop) = STOP.get() {
                stop.store(true, Ordering::Release);
            }
            // Wake a blocking ConnectNamedPipe. The server loop observes STOP
            // before creating the next instance; this connection is rejected
            // in its worker and disappears with process shutdown.
            let _ = OpenOptions::new()
                .read(true)
                .write(true)
                .open(DEFAULT_PIPE_NAME);
        }
        0
    }

    fn report(
        state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
        accepted: u32,
        wait_hint: u32,
    ) {
        let Some(raw) = STATUS.get().copied() else {
            return;
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWaitHint: wait_hint,
            ..Default::default()
        };
        unsafe {
            let _ = SetServiceStatus(SERVICE_STATUS_HANDLE(raw as *mut _), &status);
        }
    }
}
