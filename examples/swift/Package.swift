// swift-tools-version:5.9
// Lets the example build and run outside Xcode, including on Linux, where swift-crypto stands in
// for CryptoKit. An app only needs Sources/Attribution/Attribution.swift.

import PackageDescription

let package = Package(
    name: "Attribution",
    platforms: [.macOS(.v13), .iOS(.v16)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(name: "Attribution", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .executableTarget(name: "mint", dependencies: ["Attribution", .product(name: "Crypto", package: "swift-crypto")]),
    ]
)
