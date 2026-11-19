// swift-tools-version: 5.9
import PackageDescription
import Foundation

// One exact local archive input, never an SDK/name-based linker search.
let obsArchive = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent("Artifacts/MadObs/libmadobs_runtime.a").path
let package = Package(
    name: "MadCryptoPackageCheck",
    platforms: [.iOS(.v16)],
    products: [.library(name: "MadCryptoPackageCheck", targets: ["Consumer"])],
    targets: [
        .binaryTarget(name: "MadCrypto", path: "Artifacts/MadCrypto.xcframework"),
        .target(name: "Consumer", dependencies: ["MadCrypto"],
                linkerSettings: [.linkedFramework("Security"), .linkedLibrary("resolv"), .linkedLibrary("iconv")]),
        .target(name: "QualificationBridge", dependencies: ["MadCrypto"],
                publicHeadersPath: "include", cSettings: [.headerSearchPath("InstalledHeaders"), .unsafeFlags(["-UNDEBUG"])],
                cxxSettings: [.headerSearchPath("InstalledHeaders"), .unsafeFlags(["-UNDEBUG"])],
                linkerSettings: [.linkedLibrary("z"), .linkedLibrary("c++"), .unsafeFlags([obsArchive])]),
        .testTarget(name: "ConsumerTests", dependencies: ["Consumer", "QualificationBridge"])
    ], cxxLanguageStandard: .cxx17
)
