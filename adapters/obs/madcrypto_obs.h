#ifndef MADCRYPTO_OBS_ADAPTER_H
#define MADCRYPTO_OBS_ADAPTER_H
#include <madcrypto.h>
#include <madobs/observer.h>
/* Header-only opt-in integration. Host owns observer and must drain on a worker;
 * callback may run here, never while MadCrypto holds a registry lock.
 * sdk_id comes from host schema registry. timestamp is a host monotonic reading
 * at drain time (NOT the original operation time). Returns count, or -1 on error.
 * Events consumed before an observer rejection are not retried by this adapter.
 */
static inline int madcrypto_obs_drain(uint64_t session,
    const madobs_observer_v1* observer, uint32_t sdk_id,
    uint64_t monotonic_ns, unsigned budget) {
  if (!observer || observer->abi_version != MADOBS_ABI_VERSION ||
      observer->struct_size < sizeof(*observer) || !observer->emit || budget > 32)
    return -1;
  unsigned count = 0;
  while (count < budget) {
    int id = madcrypto_poll_event(session);
    if (id < 0) return -1;
    if (!id) break;
    madobs_event_v1 event = {0};
    event.struct_size = sizeof(event);
    event.abi_version = MADOBS_ABI_VERSION;
    event.sdk_id = sdk_id;
    event.sdk_version = madcrypto_abi_version();
    event.event_id = (uint32_t)id;
    event.monotonic_ns = monotonic_ns;
    if (madobs_observer_emit(observer, &event) != MADOBS_EMITTED) return -1;
    ++count;
  }
  return (int)count;
}
#endif
