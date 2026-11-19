// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MadCryptoPackageCheck",
    platforms: [.iOS(.v16)],
    products: [.library(name: "MadCryptoPackageCheck", targets: ["Consumer"])],
    targets: [
        .binaryTarget(name: "MadCrypto", path: "Artifacts/MadCrypto.xcframework"),
        .target(name: "Consumer", dependencies: ["MadCrypto"],
                linkerSettings: [.linkedFramework("Security"), .linkedLibrary("resolv"), .linkedLibrary("iconv")]),
        .testTarget(name: "ConsumerTests", dependencies: ["Consumer"])
    ]
)
