// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Privileged Windows Filtering Platform broker for strict proxy leases.
//!
//! The broker deliberately exposes one fixed operation: constrain the actual
//! AppContainer identity of a suspended child to one TCP proxy endpoint. It
//! does not accept caller-provided SIDs, filter keys, layers, actions, or
//! arbitrary conditions.

use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::{FromRawHandle, IntoRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, FILETIME,
    FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, GetLastError, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
    FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWP_MATCH_EQUAL, FWP_SID, FWP_UINT8, FWP_UINT16,
    FWP_UINT32, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK,
    FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_PACKAGE_ID,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET,
    FWPM_NET_EVENT_FLAG_IP_VERSION_SET, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, FWPM_NET_EVENT_SUBSCRIPTION0,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_NET_EVENT5, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineGetOption0, FwpmEngineOpen0, FwpmEngineSetOption0,
    FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFreeMemory0, FwpmNetEventSubscribe4,
    FwpmNetEventUnsubscribe0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, TOKEN_APPCONTAINER_INFORMATION,
    TOKEN_QUERY, TokenAppContainerSid, TokenIsAppContainer,
};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{GUID, PCWSTR, PWSTR};

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\axis-wfp-broker-v1";
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const IPPROTO_TCP: u8 = 6;
static AUDIT_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeaseRequest {
    pub version: u32,
    pub lease_id: Uuid,
    pub child_pid: u32,
    pub proxy_address: IpAddr,
    pub proxy_port: u16,
}

impl LeaseRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported WFP broker protocol version {}",
                self.version
            ));
        }
        if self.lease_id.is_nil() {
            return Err("leaseId must not be nil".into());
        }
        if self.child_pid == 0 {
            return Err("childPid must not be zero".into());
        }
        if self.proxy_port == 0 {
            return Err("proxyPort must not be zero".into());
        }
        if self.proxy_address.is_unspecified() || self.proxy_address.is_multicast() {
            return Err("proxyAddress must be a concrete unicast address".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseResponse {
    pub version: u32,
    pub lease_id: Uuid,
    pub accepted: bool,
    pub app_container_sid: Option<String>,
    pub filter_count: u32,
    pub error: Option<String>,
}

impl LeaseResponse {
    fn accepted(request: &LeaseRequest, sid: String, filter_count: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            lease_id: request.lease_id,
            accepted: true,
            app_container_sid: Some(sid),
            filter_count,
            error: None,
        }
    }

    fn rejected(lease_id: Uuid, error: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            lease_id,
            accepted: false,
            app_container_sid: None,
            filter_count: 0,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub pipe_name: String,
    pub audit_log: PathBuf,
    pub lease_dir: PathBuf,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        let root = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Self {
            pipe_name: DEFAULT_PIPE_NAME.into(),
            audit_log: root.join("axis").join("logs").join("wfp-broker.jsonl"),
            lease_dir: root.join("axis").join("wfp-leases"),
        }
    }
}

/// Non-mutating availability probe used by policy planning. It does not open
/// a lease or consume a pipe instance.
pub fn broker_available(pipe_name: &str) -> bool {
    let pipe_name = wide(pipe_name);
    unsafe { WaitNamedPipeW(PCWSTR(pipe_name.as_ptr()), 250) }.as_bool()
}

struct NetEventCollectionGuard {
    engine: HANDLE,
    restore_disabled: bool,
}

unsafe impl Send for NetEventCollectionGuard {}

struct FwpmAllocatedValue(NonNull<FWP_VALUE0>);

impl FwpmAllocatedValue {
    fn from_raw(value: *mut FWP_VALUE0) -> Result<Self, String> {
        NonNull::new(value)
            .map(Self)
            .ok_or_else(|| "FwpmEngineGetOption0 returned a null value".into())
    }

    fn get(&self) -> &FWP_VALUE0 {
        // SAFETY: a successful FwpmEngineGetOption0 call returns an allocated
        // FWP_VALUE0 that remains readable until FwpmFreeMemory0 releases it.
        unsafe { self.0.as_ref() }
    }
}

impl Drop for FwpmAllocatedValue {
    fn drop(&mut self) {
        let mut value = self.0.as_ptr();
        unsafe {
            FwpmFreeMemory0((&mut value as *mut *mut FWP_VALUE0).cast());
        }
    }
}

impl NetEventCollectionGuard {
    fn enable() -> Result<Self, String> {
        let mut engine = HANDLE::default();
        check_wfp(
            unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine) },
            "FwpmEngineOpen0(audit)",
        )?;

        let mut current = MaybeUninit::<*mut FWP_VALUE0>::uninit();
        let get_result = check_wfp(
            unsafe {
                FwpmEngineGetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, current.as_mut_ptr())
            },
            "FwpmEngineGetOption0(net events)",
        );
        if let Err(error) = get_result {
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            return Err(error);
        }
        // SAFETY: FwpmEngineGetOption0 initializes the out parameter on success.
        let current = unsafe { current.assume_init() };
        let current = match FwpmAllocatedValue::from_raw(current) {
            Ok(current) => current,
            Err(error) => {
                unsafe {
                    let _ = FwpmEngineClose0(engine);
                }
                return Err(error);
            }
        };
        let value = current.get();
        let was_enabled = unsafe { value.r#type == FWP_UINT32 && value.Anonymous.uint32 != 0 };
        drop(current);

        if !was_enabled && let Err(error) = set_net_event_collection(engine, true) {
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            return Err(error);
        }
        Ok(Self {
            engine,
            restore_disabled: !was_enabled,
        })
    }
}

impl Drop for NetEventCollectionGuard {
    fn drop(&mut self) {
        if self.restore_disabled {
            let _ = set_net_event_collection(self.engine, false);
        }
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

fn set_net_event_collection(engine: HANDLE, enabled: bool) -> Result<(), String> {
    let value = FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 {
            uint32: u32::from(enabled),
        },
    };
    check_wfp(
        unsafe { FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &value) },
        "FwpmEngineSetOption0(net events)",
    )
}

struct BrokerInstanceGuard(HANDLE);

impl BrokerInstanceGuard {
    fn acquire() -> Result<Self, String> {
        let handle = unsafe {
            CreateMutexW(
                None,
                false,
                PCWSTR(wide(r"Global\AxisWfpBrokerV1").as_ptr()),
            )
        }
        .map_err(|e| format!("create broker singleton mutex: {e}"))?;
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err("another AXIS WFP broker instance is already running".into());
        }
        Ok(Self(handle))
    }
}

impl Drop for BrokerInstanceGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Serve lease requests until `stop` becomes true.
///
/// Each accepted connection owns one dynamic WFP engine. The connection is
/// held open by `wxc-exec` for the complete sandbox lifetime, so disconnect,
/// executor crash, broker process exit, or service stop removes every filter
/// in the lease without a persistent recovery journal.
pub fn serve(config: BrokerConfig, stop: Arc<AtomicBool>) -> Result<(), String> {
    let _instance = BrokerInstanceGuard::acquire()?;
    let _net_event_collection = NetEventCollectionGuard::enable()?;
    reap_stale_leases(&config.lease_dir, &config.audit_log)?;
    while !stop.load(Ordering::Acquire) {
        let pipe = create_pipe(&config.pipe_name)?;
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if connected.is_err() {
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_CONNECTED {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                if stop.load(Ordering::Acquire) {
                    return Ok(());
                }
                return Err(format!("ConnectNamedPipe failed: {err:?}"));
            }
        }

        let child_config = config.clone();
        let raw_pipe = pipe.0 as usize;
        std::thread::spawn(move || {
            // SAFETY: ownership of the connected handle moves into File and is
            // released exactly once at the end of this worker.
            let mut stream = unsafe { File::from_raw_handle(raw_pipe as *mut c_void) };
            if let Err(error) = handle_connection(&mut stream, &child_config) {
                let _ = append_audit(
                    &child_config.audit_log,
                    serde_json::json!({
                        "event": "lease_error",
                        "error": error,
                    }),
                );
            }
            let raw = stream.into_raw_handle();
            unsafe {
                let handle = HANDLE(raw);
                let _ = DisconnectNamedPipe(handle);
                let _ = CloseHandle(handle);
            }
        });
    }
    Ok(())
}

fn handle_connection(stream: &mut File, config: &BrokerConfig) -> Result<(), String> {
    let caller_pid = pipe_client_pid(stream)?;
    let request_bytes = read_frame(stream)?;
    let parsed: Result<LeaseRequest, _> = serde_json::from_slice(&request_bytes);
    let request = match parsed {
        Ok(request) => request,
        Err(error) => {
            let response =
                LeaseResponse::rejected(Uuid::nil(), format!("invalid request: {error}"));
            write_frame(
                stream,
                &serde_json::to_vec(&response).map_err(|e| e.to_string())?,
            )?;
            return Err(response.error.unwrap_or_default());
        }
    };

    let result = (|| {
        request.validate()?;
        validate_executor_and_child(caller_pid, request.child_pid)?;
        let identity = read_app_container_identity(request.child_pid)?;
        let lease = WfpLease::install(
            &request,
            &identity.sid_bytes,
            &config.audit_log,
            &config.lease_dir,
        )?;
        Ok::<_, String>((identity.sid_string, lease))
    })();

    match result {
        Ok((sid, lease)) => {
            let response = LeaseResponse::accepted(&request, sid.clone(), lease.filter_count);
            write_frame(
                stream,
                &serde_json::to_vec(&response).map_err(|e| e.to_string())?,
            )?;
            append_audit(
                &config.audit_log,
                serde_json::json!({
                    "event": "lease_installed",
                    "leaseId": request.lease_id,
                    "callerPid": caller_pid,
                    "childPid": request.child_pid,
                    "appContainerSid": sid,
                    "proxyAddress": request.proxy_address,
                    "proxyPort": request.proxy_port,
                    "filterCount": lease.filter_count,
                }),
            )?;

            // The executor writes no more data. EOF is the lease-release signal.
            let mut discard = [0u8; 128];
            match stream.read(&mut discard) {
                Ok(_) => {}
                Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE.0 as i32) => {}
                Err(error) => return Err(format!("lease pipe read failed: {error}")),
            }
            drop(lease);
            append_audit(
                &config.audit_log,
                serde_json::json!({
                    "event": "lease_removed",
                    "leaseId": request.lease_id,
                    "childPid": request.child_pid,
                }),
            )?;
            Ok(())
        }
        Err(error) => {
            let response = LeaseResponse::rejected(request.lease_id, error.clone());
            write_frame(
                stream,
                &serde_json::to_vec(&response).map_err(|e| e.to_string())?,
            )?;
            append_audit(
                &config.audit_log,
                serde_json::json!({
                    "event": "lease_rejected",
                    "leaseId": request.lease_id,
                    "callerPid": caller_pid,
                    "childPid": request.child_pid,
                    "error": error,
                }),
            )?;
            Err(response.error.unwrap_or_default())
        }
    }
}

fn create_pipe(name: &str) -> Result<HANDLE, String> {
    let wide_name = wide(name);
    // Deny AppContainer clients explicitly. Authenticated host callers may
    // connect, after which process-image, parent, and child-token validation
    // narrow the accepted operation.
    let sddl = wide("D:P(D;;GA;;;AC)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)");
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| format!("pipe security descriptor: {e}"))?;
    }
    let attributes = windows::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide_name.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            255,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            Some(&attributes),
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    if pipe == INVALID_HANDLE_VALUE {
        Err(format!("CreateNamedPipeW failed: {:?}", unsafe {
            GetLastError()
        }))
    } else {
        Ok(pipe)
    }
}

fn pipe_client_pid(stream: &File) -> Result<u32, String> {
    use std::os::windows::io::AsRawHandle;
    let mut pid = 0;
    let handle = HANDLE(stream.as_raw_handle());
    unsafe { GetNamedPipeClientProcessId(handle, &mut pid) }
        .map_err(|e| format!("GetNamedPipeClientProcessId failed: {e}"))?;
    if pid == 0 {
        Err("named-pipe client PID was zero".into())
    } else {
        Ok(pid)
    }
}

fn validate_executor_and_child(caller_pid: u32, child_pid: u32) -> Result<(), String> {
    if caller_pid == unsafe { GetCurrentProcessId() } || caller_pid == child_pid {
        return Err("invalid executor/child PID relationship".into());
    }
    let image = process_image(caller_pid)?;
    let basename = Path::new(&image)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !basename.eq_ignore_ascii_case("wxc-exec.exe") {
        return Err(format!(
            "broker caller image must be wxc-exec.exe (got {basename:?})"
        ));
    }
    let parent = process_parent_pid(child_pid)?;
    if parent != caller_pid {
        return Err(format!(
            "suspended child PID {child_pid} is not owned by executor PID {caller_pid}"
        ));
    }
    Ok(())
}

fn process_image(pid: u32) -> Result<String, String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    };
    unsafe {
        let _ = CloseHandle(process);
    }
    result.map_err(|e| format!("QueryFullProcessImageNameW({pid}) failed: {e}"))?;
    Ok(String::from_utf16_lossy(&buffer[..len as usize]))
}

fn process_parent_pid(pid: u32) -> Result<u32, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot failed: {e}"))?;
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut found = None;
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.th32ProcessID == pid {
                found = Some(entry.th32ParentProcessID);
                break;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    unsafe {
        let _ = CloseHandle(snapshot);
    }
    found.ok_or_else(|| format!("child PID {pid} not found in process snapshot"))
}

struct AppContainerIdentity {
    sid_bytes: Vec<u8>,
    sid_string: String,
}

fn read_app_container_identity(pid: u32) -> Result<AppContainerIdentity, String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;
    let mut token = HANDLE::default();
    let token_result = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    unsafe {
        let _ = CloseHandle(process);
    }
    token_result.map_err(|e| format!("OpenProcessToken({pid}) failed: {e}"))?;

    let result = (|| {
        let mut is_app_container = 0u32;
        let mut returned = 0u32;
        unsafe {
            GetTokenInformation(
                token,
                TokenIsAppContainer,
                Some((&mut is_app_container as *mut u32).cast()),
                size_of::<u32>() as u32,
                &mut returned,
            )
        }
        .map_err(|e| format!("GetTokenInformation(TokenIsAppContainer): {e}"))?;
        if is_app_container == 0 {
            return Err("target child is not running with an AppContainer token".into());
        }

        let mut required = 0u32;
        let _ = unsafe { GetTokenInformation(token, TokenAppContainerSid, None, 0, &mut required) };
        if required < size_of::<TOKEN_APPCONTAINER_INFORMATION>() as u32 {
            return Err(format!(
                "TokenAppContainerSid reported an invalid buffer size {required}"
            ));
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut info_buffer = vec![0usize; words];
        unsafe {
            GetTokenInformation(
                token,
                TokenAppContainerSid,
                Some(info_buffer.as_mut_ptr().cast()),
                required,
                &mut returned,
            )
        }
        .map_err(|e| format!("GetTokenInformation(TokenAppContainerSid): {e}"))?;
        let info = unsafe {
            &*(info_buffer
                .as_ptr()
                .cast::<TOKEN_APPCONTAINER_INFORMATION>())
        };
        if info.TokenAppContainer.is_invalid() {
            return Err("AppContainer token returned a null package SID".into());
        }

        let sid_len = unsafe { GetLengthSid(info.TokenAppContainer) } as usize;
        if sid_len == 0 {
            return Err("GetLengthSid returned zero".into());
        }
        let sid_bytes = unsafe {
            std::slice::from_raw_parts(info.TokenAppContainer.0.cast::<u8>(), sid_len).to_vec()
        };
        let mut sid_text = PWSTR::null();
        unsafe { ConvertSidToStringSidW(info.TokenAppContainer, &mut sid_text) }
            .map_err(|e| format!("ConvertSidToStringSidW failed: {e}"))?;
        let sid_string = unsafe { sid_text.to_string() }
            .map_err(|e| format!("AppContainer SID was not valid UTF-16: {e}"))?;
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid_text.0.cast())));
        }
        Ok(AppContainerIdentity {
            sid_bytes,
            sid_string,
        })
    })();
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LeaseJournal {
    version: u32,
    lease_id: Uuid,
    child_pid: u32,
    child_creation_time: u64,
}

fn write_lease_journal(directory: &Path, journal: &LeaseJournal) -> Result<PathBuf, String> {
    std::fs::create_dir_all(directory)
        .map_err(|e| format!("create WFP lease journal directory: {e}"))?;
    let path = directory.join(format!("{}.json", journal.lease_id));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("create WFP lease journal {}: {e}", path.display()))?;
    serde_json::to_writer(&mut file, journal)
        .map_err(|e| format!("write WFP lease journal {}: {e}", path.display()))?;
    file.write_all(b"\n")
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("flush WFP lease journal {}: {e}", path.display()))?;
    Ok(path)
}

fn process_creation_time(pid: u32) -> Result<u64, String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| format!("OpenProcess({pid}) for creation time failed: {e}"))?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let result =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
    unsafe {
        let _ = CloseHandle(process);
    }
    result.map_err(|e| format!("GetProcessTimes({pid}) failed: {e}"))?;
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn reap_stale_leases(directory: &Path, audit_log: &Path) -> Result<(), String> {
    std::fs::create_dir_all(directory)
        .map_err(|e| format!("create WFP lease journal directory: {e}"))?;
    let mut journals = Vec::new();
    for entry in std::fs::read_dir(directory)
        .map_err(|e| format!("read WFP lease journal directory: {e}"))?
    {
        let entry = entry.map_err(|e| format!("read WFP lease journal entry: {e}"))?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(entry.path())
            .map_err(|e| format!("read WFP lease journal {}: {e}", entry.path().display()))?;
        let journal: LeaseJournal = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse WFP lease journal {}: {e}", entry.path().display()))?;
        if journal.version != 1
            || entry.file_name().to_string_lossy() != format!("{}.json", journal.lease_id)
        {
            return Err(format!(
                "invalid WFP lease journal identity in {}",
                entry.path().display()
            ));
        }
        journals.push((entry.path(), journal));
    }
    if journals.is_empty() {
        return Ok(());
    }

    let mut engine = HANDLE::default();
    check_wfp(
        unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine) },
        "FwpmEngineOpen0(recovery)",
    )?;
    let result = (|| {
        for (path, journal) in journals {
            terminate_matching_process(&journal)?;
            cleanup_persistent_blocks(engine, journal.lease_id)?;
            std::fs::remove_file(&path)
                .map_err(|e| format!("remove recovered WFP journal {}: {e}", path.display()))?;
            append_audit(
                audit_log,
                serde_json::json!({
                    "event": "stale_lease_reaped",
                    "leaseId": journal.lease_id,
                    "childPid": journal.child_pid,
                }),
            )?;
        }
        Ok(())
    })();
    unsafe {
        let _ = FwpmEngineClose0(engine);
    }
    result
}

fn terminate_matching_process(journal: &LeaseJournal) -> Result<(), String> {
    let process = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_TERMINATE
                | PROCESS_ACCESS_RIGHTS(0x0010_0000),
            false,
            journal.child_pid,
        )
    } {
        Ok(process) => process,
        Err(_) => return Ok(()),
    };
    let current_creation = process_creation_time(journal.child_pid);
    if current_creation == Ok(journal.child_creation_time) {
        unsafe {
            let _ = TerminateProcess(process, u32::MAX);
            let _ = WaitForSingleObject(process, 5_000);
        }
    }
    unsafe {
        let _ = CloseHandle(process);
    }
    current_creation.map(|_| ())
}

fn cleanup_persistent_blocks(engine: HANDLE, lease_id: Uuid) -> Result<(), String> {
    for discriminator in [10, 11] {
        let status = unsafe { FwpmFilterDeleteByKey0(engine, &guid_for(lease_id, discriminator)) };
        if status != 0 && status != FWP_E_FILTER_NOT_FOUND.0 as u32 {
            return Err(format!(
                "FwpmFilterDeleteByKey0(recovery) failed with 0x{status:08X}"
            ));
        }
    }
    let status = unsafe { FwpmSubLayerDeleteByKey0(engine, &guid_for(lease_id, 0)) };
    if status != 0 && status != FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
        return Err(format!(
            "FwpmSubLayerDeleteByKey0(recovery) failed with 0x{status:08X}"
        ));
    }
    Ok(())
}

struct WfpLease {
    persistent_engine: HANDLE,
    dynamic_engine: HANDLE,
    filter_count: u32,
    block_filter_ids: Vec<u64>,
    sublayer_key: GUID,
    lease_id: Uuid,
    event_handle: HANDLE,
    audit_context: Option<Box<WfpAuditContext>>,
    journal_path: Option<PathBuf>,
}

unsafe impl Send for WfpLease {}

impl Drop for WfpLease {
    fn drop(&mut self) {
        if !self.event_handle.is_invalid() {
            unsafe {
                let _ = FwpmNetEventUnsubscribe0(self.persistent_engine, self.event_handle);
            }
            self.event_handle = HANDLE::default();
        }
        self.audit_context.take();
        // Remove the proxy permit first. If cleanup is interrupted after this
        // point, the persistent blocks leave the ephemeral identity fail-closed.
        if !self.dynamic_engine.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.dynamic_engine);
            }
            self.dynamic_engine = HANDLE::default();
        }
        if !self.persistent_engine.is_invalid() {
            let cleanup = cleanup_persistent_blocks(self.persistent_engine, self.lease_id);
            unsafe {
                let _ = FwpmEngineClose0(self.persistent_engine);
            }
            self.persistent_engine = HANDLE::default();
            if cleanup.is_ok()
                && let Some(path) = self.journal_path.take()
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl WfpLease {
    fn install(
        request: &LeaseRequest,
        sid_bytes: &[u8],
        audit_log: &Path,
        lease_dir: &Path,
    ) -> Result<Self, String> {
        let mut persistent_engine = HANDLE::default();
        check_wfp(
            unsafe {
                FwpmEngineOpen0(
                    PCWSTR::null(),
                    RPC_C_AUTHN_WINNT,
                    None,
                    None,
                    &mut persistent_engine,
                )
            },
            "FwpmEngineOpen0(persistent blocks)",
        )?;
        let sublayer_key = guid_for(request.lease_id, 0);
        let mut lease = Self {
            persistent_engine,
            dynamic_engine: HANDLE::default(),
            filter_count: 0,
            block_filter_ids: Vec::with_capacity(2),
            sublayer_key,
            lease_id: request.lease_id,
            event_handle: HANDLE::default(),
            audit_context: None,
            journal_path: None,
        };

        let journal = LeaseJournal {
            version: 1,
            lease_id: request.lease_id,
            child_pid: request.child_pid,
            child_creation_time: process_creation_time(request.child_pid)?,
        };
        lease.journal_path = Some(write_lease_journal(lease_dir, &journal)?);

        check_wfp(
            unsafe { FwpmTransactionBegin0(lease.persistent_engine, 0) },
            "FwpmTransactionBegin0(persistent blocks)",
        )?;
        match lease.install_persistent_blocks(request, sid_bytes) {
            Ok(()) => {
                if let Err(error) = check_wfp(
                    unsafe { FwpmTransactionCommit0(lease.persistent_engine) },
                    "FwpmTransactionCommit0(persistent blocks)",
                ) {
                    unsafe {
                        let _ = FwpmTransactionAbort0(lease.persistent_engine);
                    }
                    return Err(error);
                }
            }
            Err(error) => {
                unsafe {
                    let _ = FwpmTransactionAbort0(lease.persistent_engine);
                }
                return Err(error);
            }
        }

        let session_name = wide(&format!("AXIS strict proxy permit {}", request.lease_id));
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(session_name.as_ptr() as *mut u16),
                description: PWSTR::null(),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 10_000,
            ..Default::default()
        };
        check_wfp(
            unsafe {
                FwpmEngineOpen0(
                    PCWSTR::null(),
                    RPC_C_AUTHN_WINNT,
                    None,
                    Some(&session),
                    &mut lease.dynamic_engine,
                )
            },
            "FwpmEngineOpen0(dynamic permit)",
        )?;
        check_wfp(
            unsafe { FwpmTransactionBegin0(lease.dynamic_engine, 0) },
            "FwpmTransactionBegin0(dynamic permit)",
        )?;
        if let Err(error) = lease.install_dynamic_allow(request, sid_bytes) {
            unsafe {
                let _ = FwpmTransactionAbort0(lease.dynamic_engine);
            }
            return Err(error);
        }
        if let Err(error) = check_wfp(
            unsafe { FwpmTransactionCommit0(lease.dynamic_engine) },
            "FwpmTransactionCommit0(dynamic permit)",
        ) {
            unsafe {
                let _ = FwpmTransactionAbort0(lease.dynamic_engine);
            }
            return Err(error);
        }
        lease.filter_count = 3;
        lease.subscribe_to_block_events(request, audit_log)?;
        Ok(lease)
    }

    fn install_persistent_blocks(
        &mut self,
        request: &LeaseRequest,
        sid_bytes: &[u8],
    ) -> Result<(), String> {
        let sublayer_name = wide(&format!("AXIS lease {}", request.lease_id));
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: self.sublayer_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sublayer_name.as_ptr() as *mut u16),
                description: PWSTR::null(),
            },
            weight: u16::MAX - 1,
            ..Default::default()
        };
        check_wfp(
            unsafe { FwpmSubLayerAdd0(self.persistent_engine, &sublayer, None) },
            "FwpmSubLayerAdd0",
        )?;

        let mut sid = sid_bytes.to_vec();
        let sid_ptr = PSID(sid.as_mut_ptr().cast());
        let block_v4 = self.add_block(
            request,
            self.sublayer_key,
            sid_ptr,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            10,
        )?;
        self.block_filter_ids.push(block_v4);
        let block_v6 = self.add_block(
            request,
            self.sublayer_key,
            sid_ptr,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            11,
        )?;
        self.block_filter_ids.push(block_v6);
        Ok(())
    }

    fn install_dynamic_allow(
        &self,
        request: &LeaseRequest,
        sid_bytes: &[u8],
    ) -> Result<(), String> {
        let permit_sublayer_key = guid_for(request.lease_id, 3);
        let name = wide(&format!("AXIS proxy permit {}", request.lease_id));
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: permit_sublayer_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_ptr() as *mut u16),
                description: PWSTR::null(),
            },
            weight: u16::MAX,
            ..Default::default()
        };
        check_wfp(
            unsafe { FwpmSubLayerAdd0(self.dynamic_engine, &sublayer, None) },
            "FwpmSubLayerAdd0(dynamic permit)",
        )?;
        let mut sid = sid_bytes.to_vec();
        let sid_ptr = PSID(sid.as_mut_ptr().cast());
        match request.proxy_address {
            IpAddr::V4(address) => {
                self.add_allow_v4(request, permit_sublayer_key, sid_ptr, address.octets())?;
            }
            IpAddr::V6(address) => {
                self.add_allow_v6(request, permit_sublayer_key, sid_ptr, address.octets())?;
            }
        }
        Ok(())
    }

    fn add_allow_v4(
        &self,
        request: &LeaseRequest,
        sublayer_key: GUID,
        sid: PSID,
        address: [u8; 4],
    ) -> Result<u32, String> {
        let mut addr = FWP_V4_ADDR_AND_MASK {
            addr: u32::from_be_bytes(address),
            mask: u32::MAX,
        };
        let mut conditions = common_allow_conditions(sid, request.proxy_port);
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: &mut addr,
                },
            },
        });
        let _ = self.add_filter(
            self.dynamic_engine,
            request,
            sublayer_key,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            1,
            u64::MAX,
            FWP_ACTION_PERMIT,
            &mut conditions,
        )?;
        Ok(1)
    }

    fn add_allow_v6(
        &self,
        request: &LeaseRequest,
        sublayer_key: GUID,
        sid: PSID,
        address: [u8; 16],
    ) -> Result<u32, String> {
        let mut addr = FWP_V6_ADDR_AND_MASK {
            addr: address,
            prefixLength: 128,
        };
        let mut conditions = common_allow_conditions(sid, request.proxy_port);
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: &mut addr,
                },
            },
        });
        let _ = self.add_filter(
            self.dynamic_engine,
            request,
            sublayer_key,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            2,
            u64::MAX,
            FWP_ACTION_PERMIT,
            &mut conditions,
        )?;
        Ok(1)
    }

    fn add_block(
        &self,
        request: &LeaseRequest,
        sublayer_key: GUID,
        sid: PSID,
        layer: GUID,
        discriminator: u8,
    ) -> Result<u64, String> {
        let mut conditions = vec![sid_condition(sid)];
        self.add_filter(
            self.persistent_engine,
            request,
            sublayer_key,
            layer,
            discriminator,
            1,
            FWP_ACTION_BLOCK,
            &mut conditions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_filter(
        &self,
        engine: HANDLE,
        request: &LeaseRequest,
        sublayer_key: GUID,
        layer: GUID,
        discriminator: u8,
        mut weight_value: u64,
        action_type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> Result<u64, String> {
        let name = wide(&format!(
            "AXIS lease {} filter {discriminator}",
            request.lease_id
        ));
        let filter = FWPM_FILTER0 {
            filterKey: guid_for(request.lease_id, discriminator),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_ptr() as *mut u16),
                description: PWSTR::null(),
            },
            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            layerKey: layer,
            subLayerKey: sublayer_key,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight_value,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action_type,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut id = 0u64;
        check_wfp(
            unsafe { FwpmFilterAdd0(engine, &filter, None, Some(&mut id)) },
            "FwpmFilterAdd0",
        )?;
        Ok(id)
    }

    fn subscribe_to_block_events(
        &mut self,
        request: &LeaseRequest,
        audit_log: &Path,
    ) -> Result<(), String> {
        if self.block_filter_ids.len() != 2 {
            return Err("strict-proxy lease did not retain both block-filter IDs".into());
        }
        let mut context = Box::new(WfpAuditContext {
            audit_log: audit_log.to_path_buf(),
            lease_id: request.lease_id,
            child_pid: request.child_pid,
            block_filter_ids: [self.block_filter_ids[0], self.block_filter_ids[1]],
        });
        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();
        let mut event_handle = HANDLE::default();
        check_wfp(
            unsafe {
                FwpmNetEventSubscribe4(
                    self.persistent_engine,
                    &subscription,
                    Some(wfp_net_event_callback),
                    Some((&mut *context as *mut WfpAuditContext).cast()),
                    &mut event_handle,
                )
            },
            "FwpmNetEventSubscribe4",
        )?;
        self.event_handle = event_handle;
        self.audit_context = Some(context);
        Ok(())
    }
}

struct WfpAuditContext {
    audit_log: PathBuf,
    lease_id: Uuid,
    child_pid: u32,
    block_filter_ids: [u64; 2],
}

unsafe extern "system" fn wfp_net_event_callback(
    context: *mut c_void,
    event: *const FWPM_NET_EVENT5,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let context = unsafe { &*(context.cast::<WfpAuditContext>()) };
    let event = unsafe { &*event };
    if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    let drop_event = unsafe { event.Anonymous.classifyDrop };
    if drop_event.is_null() {
        return;
    }
    let filter_id = unsafe { (*drop_event).filterId };
    if !context.block_filter_ids.contains(&filter_id) {
        return;
    }

    let header = &event.header;
    let remote_address = if header.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET == 0 {
        None
    } else if header.ipVersion == FWP_IP_VERSION_V4 {
        let value = unsafe { header.Anonymous2.remoteAddrV4 };
        Some(IpAddr::V4(Ipv4Addr::from(value.to_be_bytes())))
    } else if header.ipVersion == FWP_IP_VERSION_V6 {
        let value = unsafe { header.Anonymous2.remoteAddrV6.byteArray16 };
        Some(IpAddr::V6(Ipv6Addr::from(value)))
    } else {
        None
    };
    let remote_port =
        (header.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET != 0).then_some(header.remotePort);
    let protocol =
        (header.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET != 0).then_some(header.ipProtocol);
    let ip_version = (header.flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET != 0).then(|| {
        if header.ipVersion == FWP_IP_VERSION_V4 {
            4
        } else if header.ipVersion == FWP_IP_VERSION_V6 {
            6
        } else {
            0
        }
    });

    let _ = append_audit(
        &context.audit_log,
        serde_json::json!({
            "event": "connection_blocked",
            "leaseId": context.lease_id,
            "childPid": context.child_pid,
            "filterId": filter_id,
            "ipVersion": ip_version,
            "protocol": protocol,
            "remoteAddress": remote_address,
            "remotePort": remote_port,
        }),
    );
}

fn common_allow_conditions(sid: PSID, port: u16) -> Vec<FWPM_FILTER_CONDITION0> {
    vec![
        sid_condition(sid),
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: IPPROTO_TCP },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
            },
        },
    ]
}

fn sid_condition(sid: PSID) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SID,
            Anonymous: FWP_CONDITION_VALUE0_0 { sid: sid.0.cast() },
        },
    }
}

fn guid_for(lease_id: Uuid, discriminator: u8) -> GUID {
    let mut bytes = *lease_id.as_bytes();
    bytes[15] ^= discriminator;
    GUID::from_u128(u128::from_be_bytes(bytes))
}

fn check_wfp(status: u32, operation: &str) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!("{operation} failed with WFP status 0x{status:08X}"))
    }
}

fn read_frame(stream: &mut File) -> Result<Vec<u8>, String> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|e| format!("read request length: {e}"))?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(format!("invalid request length {length}"));
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("read request payload: {e}"))?;
    Ok(payload)
}

fn write_frame(stream: &mut File, payload: &[u8]) -> Result<(), String> {
    if payload.is_empty() || payload.len() > MAX_MESSAGE_BYTES {
        return Err(format!("invalid response length {}", payload.len()));
    }
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .and_then(|_| stream.write_all(payload))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("write response: {e}"))
}

fn append_audit(path: &Path, mut event: serde_json::Value) -> Result<(), String> {
    let _guard = AUDIT_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create WFP audit directory: {e}"))?;
    }
    if let Some(object) = event.as_object_mut() {
        object.insert(
            "timestampUnixMs".into(),
            serde_json::Value::from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
        );
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open WFP audit log: {e}"))?;
    let mut line =
        serde_json::to_vec(&event).map_err(|e| format!("encode WFP audit event: {e}"))?;
    line.push(b'\n');
    // One append write prevents records from separate broker generations from
    // interleaving during a service restart.
    file.write_all(&line)
        .map_err(|e| format!("write WFP audit event: {e}"))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> LeaseRequest {
        LeaseRequest {
            version: PROTOCOL_VERSION,
            lease_id: Uuid::new_v4(),
            child_pid: 123,
            proxy_address: "127.0.0.1".parse().unwrap(),
            proxy_port: 31_280,
        }
    }

    #[test]
    fn lease_request_accepts_only_concrete_nonzero_endpoint() {
        request().validate().unwrap();
        for address in ["0.0.0.0", "::", "224.0.0.1", "ff02::1"] {
            let mut invalid = request();
            invalid.proxy_address = address.parse().unwrap();
            assert!(invalid.validate().is_err(), "{address}");
        }
        let mut invalid = request();
        invalid.proxy_port = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn protocol_rejects_unknown_fields() {
        let mut value = serde_json::to_value(request()).unwrap();
        value["arbitraryFilter"] = serde_json::json!("permit all");
        assert!(serde_json::from_value::<LeaseRequest>(value).is_err());
    }

    #[test]
    fn lease_guids_are_stable_and_distinct() {
        let lease = Uuid::new_v4();
        assert_eq!(guid_for(lease, 0), guid_for(lease, 0));
        assert_ne!(guid_for(lease, 0), guid_for(lease, 1));
        assert_ne!(guid_for(lease, 1), guid_for(Uuid::new_v4(), 1));
    }
}
