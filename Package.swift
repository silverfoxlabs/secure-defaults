// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "SecureDefaults",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v12),
        .tvOS(.v12),
        .watchOS(.v5)
    ],
    products: [
        .library(name: "SecureDefaults", targets: ["SecureDefaults"]),
    ],
    dependencies: [
//        .package(url: "https://url/of/another/package/named/Utility", from: "1.0.0"),
    ],
    targets: [
        .target(name: "SecureDefaults", dependencies: []),
        .testTarget(name: "SecureDefaultsTests", dependencies: ["SecureDefaults"]),
    ]
)
