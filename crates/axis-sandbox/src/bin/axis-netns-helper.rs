// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(axis_sandbox::linux::netns::helper_main_from_env());
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("axis-netns-helper is only supported on Linux");
    std::process::exit(1);
}
