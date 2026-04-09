// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS GPU — HIP Remote para-virtual GPU isolation.
//!
//! Provides sandboxed GPU access by proxying HIP API calls from the sandbox
//! to a per-sandbox worker process that holds the real GPU context.

pub mod api_filter;
pub mod protocol;
pub mod transport;
pub mod vram_quota;
pub mod worker_mgr;
