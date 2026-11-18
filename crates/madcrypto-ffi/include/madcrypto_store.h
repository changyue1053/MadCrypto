#ifndef MADCRYPTO_STORE_H
#define MADCRYPTO_STORE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define MADCRYPTO_STORE_ABI 1u
/* Host callbacks are synchronous, borrowed pointers are valid only during call.
 * Do not retain pointers, call back into the same adapter, throw, longjmp or unwind.
 * Scope is a binary length-prefixed key; it is NOT a filesystem path.
 * load: operation_len==0 reads latest session; otherwise reads retained operation.
 * Probe uses out=NULL, capacity=0. Set out_len for both probe and actual read.
 * 0=found, 1=absent, other=IO error (never report errors as absent).
 * Never write more than capacity. Do not return success on truncation.
 * Probe/read can observe a newer authoritative record; adapter validates framing.
 */
typedef int32_t (*madcrypto_store_load_fn)(void *ctx,
    const uint8_t *scope, size_t scope_len,
    const uint8_t *operation, size_t operation_len,
    uint8_t *out, size_t capacity, size_t *out_len);
/* Must atomically CAS expected revision and insert unique per-scope operation,
 * storing latest envelope AND retained operation envelope in the same transaction.
 * has_expected=0 means insert-only. Envelope contains ONLY encrypted state/effect
 * and authenticated metadata, never raw session keys/plaintext output.
 * Outcome: 0=committed, 1=conflict/no-write, 2=rejected/no-write, 3=unknown.
 * All other codes are conservatively unknown. Never claim no-write after a write.
 * Retain operations until the application durably acknowledges their effects.
 */
typedef int32_t (*madcrypto_store_commit_fn)(void *ctx,
    const uint8_t *scope, size_t scope_len,
    uint32_t has_expected, uint64_t expected_revision, uint64_t new_revision,
    const uint8_t *operation, size_t operation_len,
    const uint8_t *envelope, size_t envelope_len);
typedef struct {
    uint32_t struct_size, abi_version;
    void *ctx;
    madcrypto_store_load_fn load;
    madcrypto_store_commit_fn commit;
} madcrypto_store_v1;
/* Rust CStoreAdapter borrows ctx. Host must keep it live for the entire adapter
 * lifetime and destroy adapter before ctx. v1 is single-thread-affine and has no
 * asynchronous callbacks or concurrent deregistration. No platform implementation
 * or durable exported session API is implied by this storage contract. */
#ifdef __cplusplus
}
#endif
#endif
