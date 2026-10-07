// swift-tools-version:6.0
// SPDX-License-Identifier: MIT
//
// The Swift client of this repository (swift/), and the driver's Swift adapter (driver/adapters/swift). SwiftPM
// takes a package from a git repository only when the manifest is at its root, so the manifest lives here and points
// into swift/:
//
//     .package(url: "https://github.com/ebremer/lws-client.git", from: "0.1.0")   // product "LWS"
import PackageDescription

let package = Package(
    name: "lws-client",
    platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16), .watchOS(.v9), .visionOS(.v1)],
    products: [
        .library(name: "LWS", targets: ["LWS"]),
        .executable(name: "lws-driver-adapter-swift", targets: ["LWSDriverAdapter"]),
    ],
    dependencies: [
        // P-256, P-384 and Ed25519 signatures, SHA-2. On Apple platforms it re-exports CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"6.0.0"),
    ],
    targets: [
        .target(
            name: "LWS",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            path: "swift/Sources/LWS"
        ),
        .testTarget(name: "LWSTests", dependencies: ["LWS"], path: "swift/Tests/LWSTests"),
        .executableTarget(name: "Quickstart", dependencies: ["LWS"], path: "swift/Examples/Quickstart"),
        .executableTarget(name: "SelfSignedAuth", dependencies: ["LWS"], path: "swift/Examples/SelfSignedAuth"),
        .executableTarget(name: "WebhookReceiver", dependencies: ["LWS"], path: "swift/Examples/WebhookReceiver"),
        .executableTarget(name: "LWSDriverAdapter", dependencies: ["LWS"], path: "driver/adapters/swift"),
    ]
)
