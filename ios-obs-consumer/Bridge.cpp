#include "Bridge.h"
#include "FixtureHook.h"
#include <madobs/runtime.h>
#include <atomic>
#include <new>
extern "C" int madcrypto_fixture_main(void);
namespace {
struct State {
  madobs_event_rule_v1 rule{};
  madobs_privacy_policy_v1 policy{};
  madobs_handle_t runtime{};
  unsigned admitted{};
  std::atomic<unsigned> batches{0}, rejected{0};
};
thread_local State *active = nullptr;
std::atomic<bool> used{false};
void consume(void *ctx, uint8_t, uint64_t, const uint8_t *bytes, size_t size,
             madobs_send_done_fn done, void *done_ctx) {
  auto &s = *static_cast<State *>(ctx);
  bool safe = s.batches.fetch_add(1) < 4 && size > 0 && size <= 1024*1024 &&
    madobs_check_private_batch(bytes, size, &s.policy) == MADOBS_PRIVATE_BATCH_OK;
  if (!safe) ++s.rejected;
  done(done_ctx, safe ? 1 : 0); // Discard locally; no endpoint or retained bytes.
}
}
extern "C" int madcrypto_test_forward(const madobs_event_v1 *e) {
  if (!active || !e || active->admitted != 0 ||
      e->struct_size != sizeof(*e) || e->abi_version != MADOBS_ABI_VERSION ||
      e->sdk_id != 42 || e->sdk_version != 0x000100 || e->event_id != 1 ||
      e->severity != 0 || e->monotonic_ns != 123 ||
      e->attribute_count != 0 || e->reserved != 0) return 0;
  for (const auto &a : e->attributes) if (a.key || a.enum_value) return 0;
  // Preserve the source event. Pinned policy constructs a zero-initialized
  // compact copy, strips exact timing, and permits no attributes.
  madobs_event_v1 clean{};
  if (madobs_sanitize_event(&active->policy, e, &clean) != MADOBS_EMITTED)
    return 0;
  if (clean.struct_size != sizeof(clean) || clean.abi_version != MADOBS_ABI_VERSION ||
      clean.sdk_id != 42 || clean.sdk_version != 0x000100 || clean.event_id != 1 ||
      clean.severity != 0 || clean.monotonic_ns != 0 ||
      clean.attribute_count != 0 || clean.reserved != 0) return 0;
  for (const auto &a : clean.attributes) if (a.key || a.enum_value) return 0;
  // This status is actual admission, unlike the adapter's void callback result.
  if (madobs_emit_generic_event(active->runtime, &clean) != MADOBS_OK) return 0;
  ++active->admitted;
  return 1;
}
extern "C" int madcrypto_test_qualification(const char *directory) {
  if (!directory || used.exchange(true)) return 0;
  auto *s = new (std::nothrow) State;
  if (!s) return 0;
  s->rule.sdk_id=42; s->rule.sdk_version=0x000100; s->rule.event_id=1;
  s->policy={sizeof(s->policy),MADOBS_ABI_VERSION,1,&s->rule};
  if (!madobs_privacy_policy_valid(&s->policy)) { delete s; return 0; }
  s->runtime=madobs_create(directory,consume,s);
  if (!s->runtime) { delete s; return 0; }
  bool ok = madobs_start(s->runtime)==MADOBS_OK;
  if (ok) {
    active=s;
    ok=madcrypto_fixture_main()==0 && s->admitted==1;
    active=nullptr;
  }
  // A shutdown failure fails qualification and retains callback-owned state.
  if (madobs_stop(s->runtime)!=MADOBS_OK) return 0;
  madobs_generic_stats_v1 stats{};
  ok=ok && madobs_get_generic_stats(s->runtime,&stats)==MADOBS_OK &&
    stats.enqueued==1 && stats.drained==1 && stats.queue_dropped==0 &&
    stats.wal_dropped==0 && s->batches.load()>0 && s->batches.load()<=4 &&
    s->rejected.load()==0;
  if (madobs_destroy(s->runtime)!=MADOBS_OK) return 0;
  delete s;
  return ok?1:0;
}
