// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Job Object resource limits for Windows sandboxes.
//!
//! Job Objects provide process count limits, memory commit limits,
//! CPU rate caps, and KILL_ON_JOB_CLOSE (if AXIS crashes, all sandbox
//! processes die automatically). No admin required.

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

/// Wrapper around a Win32 Job Object handle.
pub struct JobHandle {
    handle: HANDLE,
}

// Safety: Job handles can be sent across threads.
unsafe impl Send for JobHandle {}

impl Drop for JobHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe { let _ = CloseHandle(self.handle); }
        }
    }
}

/// Create a Job Object with resource limits.
pub fn create_job_object(
    name: &str,
    max_processes: u32,
    max_memory_mb: u64,
    cpu_rate_percent: u32,
) -> Result<JobHandle, String> {
    let job_name = HSTRING::from(name);

    let handle = unsafe {
        CreateJobObjectW(None, &job_name)
    }.map_err(|e| format!("CreateJobObjectW failed: {e}"))?;

    // Set extended limit information.
    let mut ext_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    ext_info.BasicLimitInformation.ActiveProcessLimit = max_processes;
    ext_info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    ext_info.ProcessMemoryLimit = (max_memory_mb * 1024 * 1024) as usize;

    unsafe {
        SetInformationJobObject(
            handle,
            JobObjectExtendedLimitInformation,
            &ext_info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }.map_err(|e| format!("SetInformationJobObject (limits) failed: {e}"))?;

    // Set CPU rate control.
    if cpu_rate_percent < 100 {
        let mut cpu_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
        cpu_info.ControlFlags =
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        // CpuRate is in hundredths of a percent (100 = 1%, 10000 = 100%).
        cpu_info.Anonymous.CpuRate = cpu_rate_percent * 100;

        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectCpuRateControlInformation,
                &cpu_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )
        }.map_err(|e| format!("SetInformationJobObject (CPU) failed: {e}"))?;
    }

    tracing::info!(
        "job object '{name}': max_procs={max_processes}, max_mem={max_memory_mb}MB, cpu={cpu_rate_percent}%"
    );

    Ok(JobHandle { handle })
}

/// Assign a process to a Job Object by PID.
pub fn assign_process_to_job(job: &JobHandle, pid: u32) -> Result<(), String> {
    let proc_handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, pid)
    }.map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;

    let result = unsafe {
        AssignProcessToJobObject(job.handle, proc_handle)
    };

    unsafe { let _ = CloseHandle(proc_handle); }

    result.map_err(|e| format!("AssignProcessToJobObject failed: {e}"))
}
