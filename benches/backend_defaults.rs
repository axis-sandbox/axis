// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Emit backend default decisions and benchmark evidence requirements as JSON.

fn main() {
    serde_json::to_writer_pretty(
        std::io::stdout().lock(),
        axis_core::backend_defaults::backend_default_records(),
    )
    .expect("backend default records must serialize");
    println!();
}
