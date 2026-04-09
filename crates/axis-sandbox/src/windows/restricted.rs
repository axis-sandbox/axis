// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Restricted Token creation for Windows sandboxes.
//!
//! Creates a token with all privileges stripped and integrity level
//! set to Low. No admin rights needed.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;

/// Create a restricted token from the current process token.
///
/// Returns a handle to the restricted token. The caller is responsible
/// for closing it via CloseHandle.
pub fn create_restricted_token() -> Result<HANDLE, String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token)
    }
    .map_err(|e| format!("OpenProcessToken failed: {e}"))?;

    let mut restricted_token = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            token,
            DISABLE_MAX_PRIVILEGE,
            None, // no deny-only SIDs
            None, // no privilege deletions beyond DISABLE_MAX_PRIVILEGE
            None, // no restricting SIDs
            &mut restricted_token,
        )
    }
    .map_err(|e| {
        unsafe {
            let _ = CloseHandle(token);
        }
        format!("CreateRestrictedToken failed: {e}")
    })?;

    unsafe {
        let _ = CloseHandle(token);
    }

    // Set integrity level to Low via SetTokenInformation.
    // Uses raw SID construction to avoid ConvertStringSidToSidW dependency.
    set_low_integrity(restricted_token)?;

    Ok(restricted_token)
}

/// Set the token integrity level to Low (S-1-16-4096).
/// Constructs the SID manually to avoid ConvertStringSidToSidW.
fn set_low_integrity(token: HANDLE) -> Result<(), String> {
    // S-1-16-4096 = Mandatory Label\Low Mandatory Level
    // SID structure: revision=1, sub_authority_count=1,
    //   identifier_authority={0,0,0,0,0,16}, sub_authority=[4096]
    #[repr(C)]
    struct SmallSid {
        revision: u8,
        sub_authority_count: u8,
        identifier_authority: [u8; 6],
        sub_authority: [u32; 1],
    }

    let low_sid = SmallSid {
        revision: 1,
        sub_authority_count: 1,
        identifier_authority: [0, 0, 0, 0, 0, 16], // SECURITY_MANDATORY_LABEL_AUTHORITY
        sub_authority: [4096],                       // SECURITY_MANDATORY_LOW_RID
    };

    #[repr(C)]
    struct MandatoryLabel {
        sid: *const SmallSid,
        attributes: u32,
    }

    let label = MandatoryLabel {
        sid: &low_sid,
        attributes: 0x00000020, // SE_GROUP_INTEGRITY
    };

    unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            &label as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<MandatoryLabel>() as u32,
        )
    }
    .map_err(|e| format!("SetTokenInformation (integrity level) failed: {e}"))?;

    Ok(())
}
