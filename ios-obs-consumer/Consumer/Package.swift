// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "MadCryptoPackageCheck",
    platforms: [.iOS(.v16)],
    products: [.library(name: "MadCryptoPackageCheck", targets: ["Consumer"])],
    targets: [
        .binaryTarget(name: "MadCrypto", path: "Artifacts/MadCrypto.xcframework"),
        .binaryTarget(name: "MadObs", path: "Artifacts/MadObs.xcframework"),
        .target(name: "Consumer", dependencies: ["MadCrypto"],
                linkerSettings: [.linkedFramework("Security"), .linkedLibrary("resolv"), .linkedLibrary("iconv")]),
        .target(name: "QualificationBridge", dependencies: ["MadCrypto", "MadObs"],
                publicHeadersPath: "include", cSettings: [.unsafeFlags(["-UNDEBUG"])],
                cxxSettings: [.unsafeFlags(["-UNDEBUG"])],
                linkerSettings: [.linkedLibrary("z"), .linkedLibrary("c++")]),
        .testTarget(name: "ConsumerTests", dependencies: ["Consumer", "QualificationBridge"])
    ], cxxLanguageStandard: .cxx17
)
