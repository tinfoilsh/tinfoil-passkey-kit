// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "PasskeyKeyAppleExample",
    platforms: [
        .iOS("18.0"),
        .macOS("15.0")
    ],
    products: [
        .library(name: "PasskeyKeyAppleExample", targets: ["PasskeyKeyAppleExample"])
    ],
    dependencies: [
        .package(name: "TinfoilPasskeyKit", path: "../..")
    ],
    targets: [
        .target(
            name: "PasskeyKeyAppleExample",
            dependencies: [
                .product(name: "TinfoilPasskeyKit", package: "TinfoilPasskeyKit")
            ]
        )
    ]
)
