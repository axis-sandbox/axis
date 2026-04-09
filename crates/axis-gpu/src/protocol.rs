// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HIP Remote protocol types.
//!
//! Wire format for the HIP RPC proxy. Each request is a 20-byte header
//! followed by an optional payload. The protocol is synchronous
//! request-response with correlation IDs.

use serde::{Deserialize, Serialize};

/// Protocol magic: "HIPR" = 0x48495052.
pub const MAGIC: u32 = 0x4849_5052;

/// Protocol version.
pub const VERSION: u16 = 0x0100;

/// Maximum payload size (64 MB).
pub const MAX_PAYLOAD: u32 = 64 * 1024 * 1024;

/// Flag indicating inline data follows the header.
pub const FLAG_HAS_INLINE_DATA: u32 = 1 << 0;

/// Protocol header (20 bytes, packed).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub magic: u32,
    pub version: u16,
    pub opcode: u16,
    pub request_id: u32,
    pub payload_length: u32,
    pub flags: u32,
}

/// HIP API operation categories for policy filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiCategory {
    Connection,
    DeviceManagement,
    MemoryAlloc,
    MemoryTransfer,
    MemorySet,
    MemoryInfo,
    MemoryPools,
    HostMemory,
    UnifiedMemory,
    Ipc,
    Streams,
    Events,
    Modules,
    KernelLaunch,
    FunctionAttrs,
    Occupancy,
    Graphs,
    Context,
    ErrorHandling,
    RuntimeInfo,
    Smi,
}

/// Selected opcodes from the HIP Remote protocol.
/// Full list is ~130 operations; these are the most relevant for policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Opcode {
    // Connection
    Init = 0x0001,
    Shutdown = 0x0002,
    Ping = 0x0003,

    // Device
    GetDeviceCount = 0x0101,
    SetDevice = 0x0102,
    GetDeviceProperties = 0x0103,

    // Memory
    Malloc = 0x0201,
    Free = 0x0202,
    MallocHost = 0x0203,
    FreeHost = 0x0204,
    MallocManaged = 0x0205,
    MallocAsync = 0x0206,
    FreeAsync = 0x0207,

    // Transfer
    Memcpy = 0x0301,
    MemcpyAsync = 0x0302,

    // Streams
    StreamCreate = 0x0401,
    StreamDestroy = 0x0402,
    StreamSynchronize = 0x0403,

    // Events
    EventCreate = 0x0501,
    EventDestroy = 0x0502,
    EventRecord = 0x0503,
    EventSynchronize = 0x0504,

    // Modules
    ModuleLoadData = 0x0601,
    ModuleUnload = 0x0602,
    ModuleGetFunction = 0x0603,

    // Kernel Launch
    LaunchKernel = 0x0701,
    ModuleLaunchKernel = 0x0702,

    // IPC (blocked by default)
    IpcGetMemHandle = 0x0801,
    IpcOpenMemHandle = 0x0802,
    IpcCloseMemHandle = 0x0803,

    // Device Reset (blocked by default)
    DeviceReset = 0x0104,

    // Peer Access (blocked by default)
    DeviceEnablePeerAccess = 0x0105,
}

impl Opcode {
    /// Classify an opcode into its API category.
    pub fn category(self) -> ApiCategory {
        match self {
            Self::Init | Self::Shutdown | Self::Ping => ApiCategory::Connection,
            Self::GetDeviceCount | Self::SetDevice | Self::GetDeviceProperties
            | Self::DeviceReset | Self::DeviceEnablePeerAccess => ApiCategory::DeviceManagement,
            Self::Malloc | Self::Free | Self::MallocHost | Self::FreeHost
            | Self::MallocManaged | Self::MallocAsync | Self::FreeAsync => ApiCategory::MemoryAlloc,
            Self::Memcpy | Self::MemcpyAsync => ApiCategory::MemoryTransfer,
            Self::StreamCreate | Self::StreamDestroy | Self::StreamSynchronize => ApiCategory::Streams,
            Self::EventCreate | Self::EventDestroy | Self::EventRecord
            | Self::EventSynchronize => ApiCategory::Events,
            Self::ModuleLoadData | Self::ModuleUnload | Self::ModuleGetFunction => ApiCategory::Modules,
            Self::LaunchKernel | Self::ModuleLaunchKernel => ApiCategory::KernelLaunch,
            Self::IpcGetMemHandle | Self::IpcOpenMemHandle | Self::IpcCloseMemHandle => ApiCategory::Ipc,
        }
    }
}
