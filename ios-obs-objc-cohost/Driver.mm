#import <Foundation/Foundation.h>
#import <TargetConditionals.h>
#import "Bridge.h"
#include <stdint.h>

#if !TARGET_OS_IOS || !TARGET_OS_SIMULATOR || !defined(__arm64__)
#error "This test harness requires the ARM64 iOS Simulator"
#endif

extern "C" uint32_t madcrypto_host_abi(void);
extern "C" int32_t madcrypto_host_selftest(void);

__attribute__((visibility("default")))
@interface MadCryptoCohostDriver : NSObject
+ (BOOL)abiVersionIsExpected;
+ (BOOL)existingSelftestPasses;
+ (void)runPrivateFixture:(void (^)(BOOL))completion;
@end

@implementation MadCryptoCohostDriver
+ (BOOL)abiVersionIsExpected {
    return madcrypto_host_abi() == 0x000100;
}
+ (BOOL)existingSelftestPasses {
    return madcrypto_host_selftest() == 0;
}
+ (void)runPrivateFixture:(void (^)(BOOL))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSFileManager *files=NSFileManager.defaultManager;
        NSURL *base=files.temporaryDirectory;
        NSURL *folder=[base URLByAppendingPathComponent:NSUUID.UUID.UUIDString isDirectory:YES];
        BOOL ok = folder && [files createDirectoryAtURL:folder withIntermediateDirectories:NO
                                    attributes:@{NSFilePosixPermissions:@0700} error:nil];
        if (ok) {
            ok = madcrypto_test_qualification(folder.fileSystemRepresentation) == 1;
            // A failed qualification may still own native callback state.
            if (ok) ok = [files removeItemAtURL:folder error:nil];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ completion(ok); });
    });
}
@end
