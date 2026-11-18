# Stage two: platform key protection and atomic persistence ports

## What is implemented

Rust `madcrypto_core::persistence` provides host-injected interfaces. It neither
links a platform runtime nor automatically opens a file or generates a key.
`PlatformKeyStore` provisions/deletes scoped key references and seals/opens blobs.
`AtomicSessionStore` loads records and atomically CASes a per-session revision
while storing a unique operation id plus encrypted state/effect.
`PersistentSession::update` operates on a trial state and returns output only
after a confirmed atomic commit. Definite rejection/locked keys do not advance
caller state. Conflict or ambiguous commit freezes the local instance; recovery
requires authoritative reload and reconciliation using `recover_effect`.

**This is not a production MadDB bridge, mobile key-store implementation, or
restart-safe C ABI.** Existing C handles remain memory-only and require OPK.
Low-level Rust no-OPK X3DH still requires host first-packet deduplication.

The platform key here protects serialized state at rest. It is NOT a claim that
X25519/Ed25519 protocol private keys execute inside secure hardware: loaded
ratchet keys remain in Rust process memory. Hardware-bound identity signing or
DH would require separate protocol primitive/provider design and validation.

## Adapter contracts (not platform support claims)

| Host adapter | Required responsibilities | Current evidence |
|---|---|---|
| Apple | Keychain access-group/accessibility policy; map locked/not-found distinctly; authenticated state wrapping; verify chosen hardware capabilities | Interface only, no device run |
| Android | Keystore key alias namespace, authentication/access policy, AEAD nonce handling and key invalidation mapping | Interface only, no device run |
| OHOS | HUKS/key lifecycle and access controls, algorithm support/nonce handling | Interface only, no device run |
| Host test | Actual AES-256-GCM with generated nonces and deterministic test RNG, fault-injected in-memory store | Host tests only; test key/RNG must never be deployed |

A platform may not support requested hardware-backed AEAD or user presence.
`create` must return Unsupported/Denied rather than silently lower the policy.
Do not claim Secure Enclave/StrongBox/HUKS hardware protection merely from OS API
availability. OS integration must verify actual key properties on real devices.

## Persistence boundary

Scope = app/account/session, each nonempty <=128 UTF-8 bytes without control chars.
Key reference = alias + explicit nonzero version. Metadata remains visible and
requires host privacy policy; avoid raw PII in those identifiers. Distinct length
prefixes prevent scope concatenation ambiguity in authenticated associated data.
AAD binds format, state/effect type, all scope components, alias/version, revision
and operation id. Metadata edits or swapping state/effect fail authentication.
State/effect ciphertext and plaintext have a bounded 1 MiB admission ceiling;
a provider's AEAD framing must fit within it. This is a limit, not an allocation
budget guarantee inside a host callback.

`seal` MUST use authenticated encryption and unique nonces under the selected
key, including across process restarts, concurrent writers and failed seal
attempts. Changing AAD is not a substitute for nonce uniqueness. The host owns
entropy/nonce discipline.
`open` authenticates before releasing plaintext. Missing keys cannot be silently
recreated; key loss is data loss/recovery, not an empty session.

The store must atomically write state and effect with revision CAS and unique
per-scope operation id. Reads return Result<Option<...>>: IO error never means
absence. Keep operation records until the application has acknowledged/durably
consumed them. `recover_effect` yields a committed result, not proof of network
or UI delivery; application external effects require their own idempotency.

CAS protects concurrent writers. It does NOT detect malicious rollback of the
entire store to a previously valid revision: require a trusted antirollback
anchor for that threat model. Whole-system power-loss durability also depends on
the concrete database/filesystem. Tests here inject transaction outcomes, not
real power loss.

## Recovery procedure

1. On Rejected/Locked, no write is contractually committed; retry after resolving
   the cause with the same intended operation, without publishing output early.
2. On Conflict/Unknown, the instance refuses more updates. Never reuse trial
   ciphertext, continue the old ratchet, or guess whether the operation happened.
3. Recover the host transaction store; read the operation id authoritatively.
   A present operation can be decrypted with `recover_effect`; then load the
   latest session through `PersistentSession::load` before subsequent work.
4. A missing operation after authoritative recovery can be retried from the
   recovered state. Do not use eventually consistent reads to make that decision.
5. A provider key or authentication error is not a signal to recreate identity.

The `work` closure must only compute protocol output. It must not send network
requests, publish plaintext, mutate external storage, or retain snapshots before
commit. This cannot be enforced by the Rust type system for arbitrary closures.

## Explicitly deferred security gates

- Real platform providers and Keychain/Keystore/HUKS access policies.
- Persistent identity/prekey lifecycle and atomic first-message replay handling.
- Durable C API, app-level adapter, key rotation/rewrap and deletion recovery.
- Store implementation/CAS conformance on disk, trusted rollback protection.
- Quotas/fuzzing/provider-panic and full secret-copy audit.
- Third-party cryptographic review, cross-platform devices and power-loss tests.

The wrapper freezes before entering the host commit callback. A panic after a
possible write leaves the instance recovery-required even if the application
catches unwind; no promise of panic recovery for a damaged host store is made.
Scope components are identifiers, never safe filesystem paths by themselves;
platform adapters must use a safe namespace mapping, not raw path concatenation.
An operation id must refer to one stable caller intent. Recovery cannot decide
whether a caller has accidentally reused that id for different business data.
