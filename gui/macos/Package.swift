// swift-tools-version: 5.9
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
