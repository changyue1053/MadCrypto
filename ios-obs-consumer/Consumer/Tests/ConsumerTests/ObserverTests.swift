import XCTest
import Foundation
import QualificationBridge
final class ObserverTests: XCTestCase {
    func testInstalledPrivateFixtureDrain() throws {
        #if targetEnvironment(simulator) && arch(arm64)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let status = directory.path.withCString { madcrypto_test_qualification($0) }
        XCTAssertEqual(status, 1)
        // On failure, the bridge may retain live callbacks. Teardown of this
        // job-owned simulator/process owns cleanup, never delete its WAL here.
        if status == 1 {
            try FileManager.default.removeItem(at: directory)
        }
        #else
        XCTFail("Requires ARM64 simulator")
        #endif
    }
}
