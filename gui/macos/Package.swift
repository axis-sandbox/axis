// swift-tools-version: 5.9
// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import PackageDescription

let package = Package(
    name: "AXIS",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "AXIS",
            path: "AXIS",
            resources: [
                .copy("Resources/web")
            ]
        )
    ]
)
