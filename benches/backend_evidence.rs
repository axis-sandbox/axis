// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Emit backend policy evidence counts as JSON.

fn main() {
    serde_json::to_writer_pretty(
        std::io::stdout().lock(),
        &axis_core::backend_evidence::backend_evidence_reports(),
    )
    .expect("backend evidence reports must serialize");
    println!();
}
