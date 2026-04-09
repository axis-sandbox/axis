// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS Router — inference routing, model registry, and local provider management.

pub mod backend;
pub mod config;
pub mod models;
pub mod providers;
pub mod scheduler;
pub mod server_mgr;
pub mod smart_routing;
pub mod token_budget;
