// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "TinfoilPasskeyKit",
    platforms: [
        .iOS("18.0"),
        .macOS("15.0")
    ],
    products: [
        .library(
            name: "TinfoilPasskeyKit",
            targets: ["TinfoilPasskeyKit"]
        )
    ],
    targets: [
        .target(name: "TinfoilPasskeyKit"),
        .testTarget(
            name: "TinfoilPasskeyKitTests",
            dependencies: ["TinfoilPasskeyKit"]
        )
    ]
)
