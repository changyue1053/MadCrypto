#include <assert.h>
#include "madcrypto_obs.h"
static unsigned received;
static void collect(void *ctx, const madobs_event_v1 *event) {
  (void)ctx;
  assert(event->sdk_id == 42);
  assert(event->event_id == 1);
  assert(event->attribute_count == 0);
  received++;
}
int main(void) {
  uint8_t bundle[512], packet[1024];
  int64_t bob = madcrypto_identity_new(), alice = madcrypto_identity_new();
  assert(bob > 0 && alice > 0);
  assert(madcrypto_bundle_publish((uint64_t)bob) == 0);
  int64_t n = madcrypto_take_pending((uint64_t)bob, bundle, sizeof(bundle));
  assert(n > 0 && n <= (int64_t)sizeof(bundle));
  int64_t session = madcrypto_session_initiate((uint64_t)alice, bundle, (size_t)n,
                                              (const uint8_t*)"x", 1, 0, 0);
  assert(session > 0);
  assert(madcrypto_take_pending((uint64_t)session, packet, sizeof(packet)) > 0);
  assert(madcrypto_poll_event((uint64_t)session) == 0);
  assert(madcrypto_observe((uint64_t)session, 1) == 0);
  assert(madcrypto_session_encrypt((uint64_t)session, 0, 0, (const uint8_t*)"y", 1) == 0);
  madobs_observer_v1 observer = {sizeof(observer), MADOBS_ABI_VERSION, 0, collect};
  assert(madcrypto_obs_drain((uint64_t)session, &observer, 42, 123, 32) == 1);
  assert(received == 1);
  assert(madcrypto_observation_drops((uint64_t)session) == 0);
  assert(madcrypto_session_free((uint64_t)session) == 0);
  assert(madcrypto_poll_event((uint64_t)session) < 0);
  madcrypto_identity_free((uint64_t)alice);
  madcrypto_identity_free((uint64_t)bob);
  return 0;
}
