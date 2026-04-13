// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "WireGuardKit",
    platforms: [
        .macOS(.v12),
        .iOS(.v15)
    ],
    products: [
        .library(name: "WireGuardKit", targets: ["WireGuardKit"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "WireGuardKit",
            dependencies: ["WireGuardKitGo", "WireGuardKitC"]
        ),
        .target(
            name: "WireGuardKitC",
            dependencies: [],
            publicHeadersPath: "."
        ),
        .target(
            name: "WireGuardKitGo",
            dependencies: [],
            exclude: [
                "goruntime-boottime-over-monotonic.diff",
                "go.mod",
                "go.sum",
                "Makefile",
                "api-apple.go",
                "api-xray.go",
                "turn-proxy-api.go",
                "turn-proxy.h",
                "turn-proxy-botgen.go",
                "turn-proxy-captcha-slider.go",
                "turn-proxy-creds.go",
                "turn-proxy-dispatcher.go",
                "turn-proxy-globals.go",
                "turn-proxy-group.go",
                "turn-proxy-namegen.go",
                "turn-proxy-protocol.go",
                "turn-proxy-session.go",
                "turn-proxy-split.go",
                "turn-proxy-stats.go",
            ],
            publicHeadersPath: "."
        ),
        .testTarget(
            name: "WireGuardKitTests",
            dependencies: ["WireGuardKit"]
        )
    ]
)
