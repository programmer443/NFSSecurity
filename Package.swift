// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "NFSSecurity",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "NFSSecurity",
            targets: ["NFSSecurity"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NFSSecurity",
            dependencies: [],
            path: "Sources/NFSSecurity"),
        .testTarget(
            name: "NFSSecurityTests",
            dependencies: ["NFSSecurity"],
            path: "Tests/NFSSecurityTests"
        ),
    ]
)
