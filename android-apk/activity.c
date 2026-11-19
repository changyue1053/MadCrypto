/* Packaging only: no keys, selftest, protocol, state, telemetry or app execution. */
#include <android/native_activity.h>
#include <madcrypto.h>
void ANativeActivity_onCreate(ANativeActivity *activity, void *state, size_t size) {
    (void)activity; (void)state; (void)size;
    (void)madcrypto_abi_version();
}
