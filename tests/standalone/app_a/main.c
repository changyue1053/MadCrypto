#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "madcrypto.h"

#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
enum { CANARY = 0xA5, MAX_ERROR = 1024 };

static int untouched(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != CANARY) return 0;
    }
    return 1;
}

static int pending_ownership(uint64_t handle) {
    CHECK(madcrypto_bundle_publish(handle) == 0);
    CHECK(madcrypto_bundle_publish(handle) < 0);
    int64_t need = madcrypto_take_pending(handle, NULL, 0);
    CHECK(need > 1 && need <= 65536);
    size_t size = (size_t)need;
    uint8_t *bytes = malloc(size + 2);
    CHECK(bytes != NULL);
    memset(bytes, CANARY, size + 2);
    int ok = madcrypto_take_pending(handle, bytes + 1, size - 1) == need
        && untouched(bytes, size + 2)
        && madcrypto_take_pending(handle, NULL, 0) == need
        && madcrypto_take_pending(handle, bytes + 1, size) == need
        && bytes[0] == CANARY && bytes[size + 1] == CANARY
        && !untouched(bytes + 1, size)
        && madcrypto_take_pending(handle, NULL, 0) < 0;
    free(bytes);
    CHECK(ok);

    /* Free the SDK identity with a different fresh pending output still held. */
    CHECK(madcrypto_bundle_publish(handle) == 0);
    CHECK(madcrypto_take_pending(handle, NULL, 0) > 0);
    CHECK(madcrypto_identity_free(handle) == 0);
    uint8_t stale[16];
    memset(stale, CANARY, sizeof(stale));
    CHECK(madcrypto_take_pending(handle, stale, sizeof(stale)) < 0);
    CHECK(untouched(stale, sizeof(stale)));
    CHECK(madcrypto_bundle_publish(handle) < 0);
    return 0;
}

struct error_copy {
    int32_t length;
    uint8_t bytes[MAX_ERROR];
};

static int snapshot_error(struct error_copy *copy) {
    uint8_t guarded[MAX_ERROR + 2];
    memset(guarded, CANARY, sizeof(guarded));
    int32_t length = madcrypto_last_error(NULL, 0);
    if (length < 2 || length >= MAX_ERROR) return 0;
    if (madcrypto_last_error(guarded + 1, 0) != length || !untouched(guarded, sizeof(guarded))) return 0;
    const size_t short_capacity = (size_t)length - 1;
    if (madcrypto_last_error(guarded + 1, short_capacity) != length ||
        guarded[0] != CANARY || untouched(guarded + 1, short_capacity) ||
        !untouched(guarded + 1 + short_capacity, sizeof(guarded) - 1 - short_capacity)) return 0;
    memcpy(copy->bytes, guarded + 1, short_capacity);
    memset(guarded, CANARY, sizeof(guarded));
    /* Extra capacity exists; the ABI copies only message bytes, no NUL. */
    if (madcrypto_last_error(guarded + 1, MAX_ERROR) != length ||
        guarded[0] != CANARY ||
        !untouched(guarded + 1 + (size_t)length, sizeof(guarded) - 1 - (size_t)length) ||
        memcmp(guarded + 1, copy->bytes, short_capacity) != 0) return 0;
    memcpy(copy->bytes, guarded + 1, (size_t)length);
    copy->length = length;
    return 1;
}

static int matches_error(const struct error_copy *copy) {
    struct error_copy after = {0};
    return copy->length > 0 && snapshot_error(&after) && after.length == copy->length &&
        memcmp(after.bytes, copy->bytes, (size_t)copy->length) == 0;
}

struct thread_case {
    pthread_barrier_t barrier;
    uint64_t worker_identity;
    struct error_copy worker_error;
    int worker_ok;
};

static void rendezvous(struct thread_case *state) {
    /* Both participants always hit all four rendezvous, even on failed checks. */
    (void)pthread_barrier_wait(&state->barrier);
}

static void *worker(void *ctx) {
    struct thread_case *state = ctx;
    int ok = madcrypto_take_pending(0, NULL, 0) < 0 &&
        snapshot_error(&state->worker_error);
    rendezvous(state); /* Worker error is set before caller writes its own. */
    rendezvous(state);
    ok &= matches_error(&state->worker_error);
    rendezvous(state); /* Caller has verified its own still-live error. */
    ok &= madcrypto_identity_free(state->worker_identity) == 0;
    ok &= madcrypto_last_error(NULL, 0) == 0;
    rendezvous(state); /* Worker cleared its TLS; caller's error must survive. */
    state->worker_ok = ok;
    return NULL;
}

static int thread_ownership(void) {
    struct thread_case state = {0};
    int64_t own = madcrypto_identity_new();
    CHECK(own > 0);
    int64_t other = madcrypto_identity_new();
    if (other <= 0) {
        (void)madcrypto_identity_free((uint64_t)own);
        return __LINE__;
    }
    state.worker_identity = (uint64_t)other;
    if (pthread_barrier_init(&state.barrier, NULL, 2) != 0) {
        (void)madcrypto_identity_free((uint64_t)own);
        (void)madcrypto_identity_free((uint64_t)other);
        return __LINE__;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, &state) != 0) {
        (void)pthread_barrier_destroy(&state.barrier);
        (void)madcrypto_identity_free((uint64_t)own);
        (void)madcrypto_identity_free((uint64_t)other);
        return __LINE__;
    }
    struct error_copy own_error = {0};
    rendezvous(&state);
    /* Wrong-kind free must not destroy this valid identity. */
    int ok = madcrypto_session_free((uint64_t)own) < 0 && snapshot_error(&own_error);
    ok &= own_error.length > 0 && state.worker_error.length > 0 &&
        (own_error.length != state.worker_error.length ||
         memcmp(own_error.bytes, state.worker_error.bytes, (size_t)own_error.length) != 0);
    rendezvous(&state);
    ok &= matches_error(&own_error);
    rendezvous(&state);
    rendezvous(&state);
    ok &= matches_error(&own_error);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(pthread_barrier_destroy(&state.barrier) == 0);
    ok &= state.worker_ok;
    ok &= madcrypto_bundle_publish((uint64_t)own) == 0; /* Wrong-kind free retained it. */
    ok &= madcrypto_identity_free((uint64_t)own) == 0;
    ok &= madcrypto_last_error(NULL, 0) == 0;
    ok &= madcrypto_take_pending((uint64_t)own, NULL, 0) < 0;
    ok &= madcrypto_bundle_publish((uint64_t)other) < 0;
    CHECK(ok);
    return 0;
}

int main(void) {
    CHECK(madcrypto_abi_version() == 0x000100);
    CHECK(madcrypto_selftest() == 0);
    int64_t identity = madcrypto_identity_new();
    CHECK(identity > 0);
    int result = pending_ownership((uint64_t)identity);
    if (result) {
        (void)madcrypto_identity_free((uint64_t)identity);
        return result;
    }
    return thread_ownership();
}
