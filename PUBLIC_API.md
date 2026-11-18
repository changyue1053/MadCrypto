# Stage-one public contracts

## Protocol/storage

`SecureSession::snapshot()` creates an independent trial state.
`receive_and_commit` decrypts on a trial, commits message+new state atomically,
then replaces caller state. The supplied SessionStore must serialize operations
for the same session and atomically fail or commit. Its `contains_message`
namespace must be scoped by tenant/account/store so IDs cannot collide across
accounts. Database/IO errors must not masquerade as absence. The current legacy
Option/bool lookup shape is limited; richer Result/CAS store revision is future
work. If commit returns an ambiguous outcome, stop and recover/reload storage;
do not assume retrying memory state is safe. No cross-library DB pointer API.

`ResponderKeys.one_time_prekey_private` is now borrowed: callers consume it only
after first-message authentication and their atomic state commit. This is a
source-level Rust API change from IMCrypto. There is no new wire protocol.

Rust low-level X3DH supports no-OPK establishment. That path does NOT provide
persistent first-packet deduplication; host must implement it and cannot infer
replay protection from successful decryption. The C facade rejects no-OPK
bundles/first packets by default because it has no persistent replay store.

## C ABI

`madcrypto_abi_version()` is 0.1.0. This is a new Mad namespace, not a binary
replacement for `imct_*`. Positive session/identity handles share a process
registry; operations serialize behind its mutex. Handles increase and are not
reused in ordinary operation; exhaustion guarantees/host instance handles are
not implemented. Apps are separate processes; within a process the host must
maintain account-to-handle ownership. No claim of multi-tenant access control.

Intl wire v1 limits are 65,472 plaintext bytes for initiate (64KiB inner
frame minus 48-byte header minus 16-byte tag) and 65,520 for subsequent encrypt.
Larger inputs are rejected before state changes. Wrong-type free is rejected
without clearing pending output.

Operations are synchronous. Do not call on UI threads. Pending output is one
slot per handle; consume before next publish/encrypt/decrypt. NULL always probes;
a non-NULL valid buffer consumes when capacity suffices (even length zero).
`free` removes state and pending bytes, repeated free returns success. Input
pointers must be valid and readable for lengths; invalid pointers remain caller
UB. No callback API, cancellation or asynchronous close is promised in v0.

## Optional observation

`madcrypto_observe(session,1)` enables a 32-entry queue, default disabled.
`poll_event`: 0 empty/disabled, 1 encrypted, 2 decrypted, negative invalid handle.
No plaintext, keys, message IDs, paths, byte counts or caller strings enter this
schema. Overflow drops new events and increments a saturating counter readable
via `madcrypto_observation_drops`. Disable/free discards queue. SDK does not
spawn a telemetry thread or link MadObs. Host controls polling frequency.

`adapters/obs/madcrypto_obs.h` optionally consumes the independently distributed
MadObs observer header. Host supplies SDK schema ID, clock reading, observer and
bounded drain budget (<=32). It emits on the calling drain thread, outside SDK
locks. Timestamp is drain time, not original operation time. Host callback must
not block/throw and must outlive drain; no concurrent unregistration. Queue
admission/export failure is not a cryptographic operation failure. Consumed
observations are not retried. Adapter test uses a real observer contract and
recording sink, NOT a claim of network exporter verification.

## Stage-two persistence ports

`persistence::{PlatformKeyStore, AtomicSessionStore, PersistentSession}` adds a
Rust-only authenticated snapshot/effect path with scoped key references and CAS.
The typed ports replace absence/error ambiguity for this path; they do not
silently change the legacy `SessionStore` API. See
[platform-persistence contract](docs/security/platform-persistence.md).
No real OS key-store adapter, durable C handle or MadDB dependency is introduced.
