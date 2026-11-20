#import <UIKit/UIKit.h>
#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

extern uint32_t madcrypto_host_abi(void);
extern int32_t madcrypto_host_selftest(void);
extern int madcrypto_test_qualification(const char *);

static BOOL validNonce(NSString *nonce) {
    if (nonce.length != 32) return NO;
    for (NSUInteger i = 0; i < nonce.length; ++i) {
        unichar c = [nonce characterAtIndex:i];
        if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return NO;
    }
    return YES;
}

static void publish(NSString *cache, NSDictionary *receipt) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:receipt options:0 error:nil];
    if (!data || data.length > 4096) return;
    NSString *partial = [cache stringByAppendingPathComponent:@"madcrypto-direct.partial"];
    NSString *result = [cache stringByAppendingPathComponent:@"madcrypto-direct.json"];
    int fd = open(partial.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    const uint8_t *bytes = data.bytes;
    size_t offset = 0;
    while (offset < data.length) {
        ssize_t n = write(fd, bytes + offset, data.length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        offset += (size_t)n;
    }
    BOOL ready = offset == data.length && fsync(fd) == 0;
    if (close(fd) != 0) ready = NO;
    // Same-directory hard link is one atomic, non-overwriting publication.
    // If publication fails no replacement of any previous receipt is possible.
    if (ready) (void)link(partial.fileSystemRepresentation, result.fileSystemRepresentation);
    (void)unlink(partial.fileSystemRepresentation);
}

@interface QualificationAppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation QualificationAppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    (void)app; (void)opts;
#if TARGET_OS_SIMULATOR && defined(__arm64__)
    NSArray<NSString *> *args = NSProcessInfo.processInfo.arguments;
    NSString *nonce = args.count == 2 ? args[1] : nil;
    if (!validNonce(nonce)) return YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSFileManager *files = NSFileManager.defaultManager;
        NSString *cache = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
        if (!cache || ![files createDirectoryAtPath:cache withIntermediateDirectories:YES attributes:nil error:nil]) return;
        NSString *drain = [cache stringByAppendingPathComponent:@"madcrypto-direct-drain"];
        if (![files createDirectoryAtPath:drain withIntermediateDirectories:NO
                               attributes:@{NSFilePosixPermissions:@0700} error:nil]) return;
        BOOL abi = madcrypto_host_abi() == 0x000100;
        BOOL selftest = madcrypto_host_selftest() == 0;
        BOOL drained = madcrypto_test_qualification(drain.fileSystemRepresentation) == 1;
        if (drained) drained = [files removeItemAtPath:drain error:nil];
        publish(cache,@{@"version":@1, @"nonce":nonce, @"pid":@(getpid()),
                         @"outcomes":@{@"testInstalledABIVersion":(abi ? @YES : @NO),
                                       @"testInstalledExistingSelftest":(selftest ? @YES : @NO),
                                       @"testInstalledPrivateFixtureDrain":(drained ? @YES : @NO)}});
    });
#endif
    return YES;
}
@end
int main(int argc, char **argv) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([QualificationAppDelegate class]));
    }
}
