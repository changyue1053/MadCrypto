#import <XCTest/XCTest.h>
#import <TargetConditionals.h>
#if !TARGET_OS_IOS || !TARGET_OS_SIMULATOR || !defined(__arm64__)
#error "These tests require the ARM64 iOS Simulator"
#endif

/* Only this Objective-C class is resolved through the host executable. */
@interface MadCryptoCohostDriver : NSObject
+ (BOOL)abiVersionIsExpected;
+ (BOOL)existingSelftestPasses;
+ (void)runPrivateFixture:(void (^)(BOOL))completion;
@end

@interface PackageTests : XCTestCase
@end
@implementation PackageTests
- (void)testInstalledABIVersion {
    XCTAssertTrue([MadCryptoCohostDriver abiVersionIsExpected]);
}
- (void)testInstalledExistingSelftest {
    XCTAssertTrue([MadCryptoCohostDriver existingSelftestPasses]);
}
@end

@interface ObserverTests : XCTestCase
@end
@implementation ObserverTests
- (void)testInstalledPrivateFixtureDrain {
    XCTestExpectation *done=[self expectationWithDescription:@"private app fixture completed"];
    [MadCryptoCohostDriver runPrivateFixture:^(BOOL success) {
        XCTAssertTrue(success);
        [done fulfill];
    }];
    [self waitForExpectationsWithTimeout:30.0 handler:nil];
}
@end
