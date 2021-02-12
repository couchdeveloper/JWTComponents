// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JWTComponents",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "JWTComponents",
            targets: ["JWTComponents"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        //.package(name: "CryptorRSA", url: "https://github.com/Kitura/BlueRSA.git", from: "1.0.2"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "JWTComponents",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(
            name: "JWTComponentsTests",
            dependencies: ["JWTComponents"]),
    ]
)
