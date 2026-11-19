#ifndef MADCRYPTO_TEST_FIXTURE_HOOK_H
#define MADCRYPTO_TEST_FIXTURE_HOOK_H
#include <madobs/observer.h>
#ifdef __cplusplus
extern "C" {
#endif
int madcrypto_test_forward(const madobs_event_v1 *event);
#ifdef __cplusplus
}
#endif
#endif
