// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AppContainer profile management for Windows network isolation.
//!
//! Uses the Windows AppContainer API (userenv.dll) to create isolated
//! execution contexts with zero network capabilities. The proxy is
//! reachable via loopback exemption.

/// Create an AppContainer profile. Returns the SID string.
pub fn create_appcontainer_profile(name: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    return create_profile_impl(name);

    #[cfg(not(target_os = "windows"))]
    {
        let _ = name;
        Err("AppContainer only available on Windows".into())
    }
}

/// Delete an AppContainer profile.
pub fn delete_appcontainer_profile(name: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    return delete_profile_impl(name);

    #[cfg(not(target_os = "windows"))]
    {
        let _ = name;
        Ok(())
    }
}

/// Enable loopback exemption for a sandbox's AppContainer.
pub fn enable_loopback(name: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    return enable_loopback_impl(name);

    #[cfg(not(target_os = "windows"))]
    {
        let _ = name;
        Ok(())
    }
}

// ── Windows implementation ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn create_profile_impl(name: &str) -> Result<String, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Call CreateAppContainerProfile via raw FFI (userenv.dll).
    // This avoids depending on specific windows crate feature sets
    // that may not be available for cross-compilation.

    type PSID = *mut std::ffi::c_void;

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn CreateAppContainerProfile(
            pszAppContainerName: *const u16,
            pszDisplayName: *const u16,
            pszDescription: *const u16,
            pCapabilities: *const std::ffi::c_void,
            dwCapabilityCount: u32,
            ppSidAppContainerSid: *mut PSID,
        ) -> i32; // HRESULT

        fn DeleteAppContainerProfile(
            pszAppContainerName: *const u16,
        ) -> i32;

        fn DeriveAppContainerSidFromAppContainerName(
            pszAppContainerName: *const u16,
            ppsidAppContainerSid: *mut PSID,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertSidToStringSidW(
            Sid: PSID,
            StringSid: *mut *mut u16,
        ) -> i32; // BOOL
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn sid_to_string(psid: PSID) -> Result<String, String> {
        let mut string_sid: *mut u16 = std::ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(psid, &mut string_sid) };
        if ok == 0 {
            return Err("ConvertSidToStringSidW failed".into());
        }
        let result = unsafe {
            let len = (0..).take_while(|&i| *string_sid.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(string_sid, len))
        };
        unsafe { LocalFree(string_sid as *mut _); }
        Ok(result)
    }

    let name_w = to_wide(name);
    let display_w = to_wide("AXIS Sandbox");
    let desc_w = to_wide("Isolated agent execution environment");
    let mut psid: PSID = std::ptr::null_mut();

    let hr = unsafe {
        CreateAppContainerProfile(
            name_w.as_ptr(),
            display_w.as_ptr(),
            desc_w.as_ptr(),
            std::ptr::null(),
            0, // zero capabilities = full network deny
            &mut psid,
        )
    };

    if hr == 0 {
        // Success.
        let sid_str = sid_to_string(psid)?;
        unsafe { LocalFree(psid); }
        tracing::info!("AppContainer '{name}' created: {sid_str}");
        return Ok(sid_str);
    }

    // 0x800705B9 = ERROR_ALREADY_EXISTS
    if hr as u32 == 0x800705B9u32 {
        // Profile exists — derive the SID.
        let mut psid2: PSID = std::ptr::null_mut();
        let hr2 = unsafe {
            DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut psid2)
        };
        if hr2 == 0 {
            let sid_str = sid_to_string(psid2)?;
            unsafe { LocalFree(psid2); }
            tracing::info!("AppContainer '{name}' already exists: {sid_str}");
            return Ok(sid_str);
        }
        return Err(format!("DeriveAppContainerSid failed: HRESULT 0x{hr2:08X}"));
    }

    Err(format!("CreateAppContainerProfile failed: HRESULT 0x{hr:08X}"))
}

#[cfg(target_os = "windows")]
fn delete_profile_impl(name: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn DeleteAppContainerProfile(pszAppContainerName: *const u16) -> i32;
    }

    let name_w: Vec<u16> = OsStr::new(name).encode_wide().chain(std::iter::once(0)).collect();
    let hr = unsafe { DeleteAppContainerProfile(name_w.as_ptr()) };
    if hr == 0 {
        tracing::info!("AppContainer '{name}' deleted");
        Ok(())
    } else {
        Err(format!("DeleteAppContainerProfile: HRESULT 0x{hr:08X}"))
    }
}

#[cfg(target_os = "windows")]
fn enable_loopback_impl(name: &str) -> Result<(), String> {
    // NetworkIsolationSetAppContainerConfig is in firewallapi.dll.
    // It requires the AppContainer SID. For a simpler path, we use
    // CheckNetIsolation.exe which is available on all Windows 11 systems.

    let output = std::process::Command::new("CheckNetIsolation")
        .args(["LoopbackExempt", "-a", &format!("-n={name}")])
        .output()
        .map_err(|e| format!("CheckNetIsolation: {e}"))?;

    if output.status.success() {
        tracing::info!("loopback exemption enabled for '{name}'");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Non-fatal — loopback may already be exempted.
        tracing::warn!("CheckNetIsolation: {stderr}");
        Ok(())
    }
}
