// swift-tools-version: 5.10.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwobDoubleRatchet",
    platforms: [.macOS(.v14), .iOS("13.0"), .watchOS(.v8)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwobDoubleRatchet",
            targets: ["SwobDoubleRatchet"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift", from: "1.8.2")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwobDoubleRatchet",
            dependencies: ["CryptoSwift"]),
        .testTarget(
            name: "SwobDoubleRatchetTest",
            dependencies: ["SwobDoubleRatchet"]
        ),
    ]
)
