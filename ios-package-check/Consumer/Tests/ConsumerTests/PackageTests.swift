import XCTest
import Consumer

final class PackageTests: XCTestCase {
    func testInstalledABIVersion() {
        XCTAssertEqual(PackageProbe.abiVersion(), 0x000100)
    }
    func testInstalledExistingSelftest() {
        XCTAssertEqual(PackageProbe.existingSelftest(), 0)
    }
}
