#ifndef MADCRYPTO_TEST_OBS_BRIDGE_H
#define MADCRYPTO_TEST_OBS_BRIDGE_H
#include <madobs/observer.h>
#ifdef __cplusplus
extern "C" {
#endif
int madcrypto_test_forward(const madobs_event_v1 *event);
/* Once per process, sequential, unique disposable local directory. */
int madcrypto_test_qualification(const char *directory);
#ifdef __cplusplus
}
#endif
#endif
