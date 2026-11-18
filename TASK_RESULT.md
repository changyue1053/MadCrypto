# Stage-one implementation result — 2026-11-18

Task cards: A00/A01 baseline and source hygiene; C01/C02 host protocol/FFI
subset; X01 optional observation adapter prototype. **PARTIAL overall SDK plan.**
No IMSDK, product DB bridge, mobile package, device certification or formal release.

## Source and isolated changes

Source IMCrypto f52729c289d3bdd413fcca88706f45507ff401b9 (`imcrypto/`), original
43 files preserved in local baseline bfe062e; renaming/provenance separately
committed as f4d08e4. Source-only public migration is owner-directed. Proprietary
metadata retained; no new open-source grant. No vendored third-party source was
added. Registry dependencies remain pinned by Cargo.lock.

## Implemented

- Independent MadCrypto package names, C symbol/header namespace and default
  build with no SQLCipher, MadDB, MadObs runtime or IMSDK dependency.
- Trial-state receive commits before mutating caller state; definite store
  failure does not advance the live ratchet. Reference SQLCipher store retained.
- Pending output cannot be overwritten by publish/encrypt/decrypt; pending
  buffers zeroize on drop; NULL probing handles empty plaintext safely.
- Failed first-packet authentication no longer burns OPK. C facade rejects
  no-OPK bundles/first packets. Rust primitive retains no-OPK support with explicit
  host replay-store obligations; no persistent replay claim is made.
- Wrong-type free rejects without clearing live output. Wire plaintext size
  limits checked before mutation: 65472 first-message, 65520 regular-message.
- Optional per-session 32-event numeric queue, drop counter, host polling and
  header-only MadObs adapter. No user data or callbacks on protocol execution path.
- Test-only panic trigger not exported by distributable native library.

## Actual verification

- Clean original source in a separate checkout: 95 tests passed, 0 failed,
  2 intentionally ignored SM2 stress tests. Original initial attempt was interrupted
  by source renaming; only the clean rerun is accepted as baseline evidence.
- Modified workspace: 97 passed, 0 failed, same 2 ignored SM2 stress tests.
- Included real C ABI full handshake/ratchet roundtrip and boundary regressions,
  RFC primitive vectors, deterministic randomized tests and SQLCipher transaction tests.
- Clippy workspace/all-targets with `-D warnings`: passed. Cargo manifest warnings
  for inherited unused `hmac` and unused rust-version remain, not compiler findings.
- Independent C static-library consumer: passed.
- MadObs header-contract recording sink consumer: passed. Real MadObs runtime,
  network exporter and cross-SDK binary coexistence are NOT verified.
- Linux .so exports only 15 expected `madcrypto_*` symbols; no debug panic export.
- Source hygiene pattern scan: zero candidates. Dependency license metadata
  inventory: 112 packages, no missing license fields; native transitive license
  texts/NOTICE and a full supply-chain/security audit remain binary-release gates.

Reproduce via `MADOBS_INCLUDE_DIR=/path/to/MadObs/include scripts/verify.sh`.
Actual toolchain: Linux x86_64, Rust 1.100.0 and system C compiler. No claim of
1.85 MSRV, iOS, Android, OHOS or production-readiness verification.

## Remaining work and rollback

Persistent C identities/sessions, sender state+outbox transaction port, richer
store lookup errors/CAS, host instance/account isolation, input/resource quotas,
registry exhaustion/poisoning policy, full secret-temporary audit, independent
protocol interoperability, external security audit, FFI fuzz/sanitizers, mobile
bindings and real devices remain open. Read SECURITY.md and PUBLIC_API.md.

No intentional wire/KDF/state serialization changes. Rust OPK parameter now
borrows; C namespace renamed. Roll back source to a recorded commit only; do not
roll back live protocol state or reuse consumed keys. There is no new disk schema.

## Stage-two implementation (2026-11-18)

Rust-only scoped PlatformKeyStore and AtomicSessionStore ports, authenticated
state/effect envelope and PersistentSession CAS/recovery handling added. Wrapping
keys remain provider-owned; protocol keys still reside in Rust memory after load.
Provider access policies are contracts, not implemented OS guarantees.

Actual host result: 110 tests passed, 0 failed, 2 SM2 stress tests ignored;
13 new persistence cases. Full Clippy and independent C/optional MadObs header
consumers passed again. Source hygiene scan has zero candidates; no dependency
added (112 metadata inventory entries). See docs/verification/STAGE2.md.

Still no real platform key-store, disk CAS implementation, persistent identity/
prekey lifecycle, antirollback anchor, durable C API, device run or external
cryptographic audit. This is an interface+coordinator milestone, not a production
persistence release. Stage-one no-OPK behavior restriction is unchanged.

## Stage-three implementation (2026-11-18)

C encrypted-store callback contract + thread-affine Rust CStoreAdapter and bounded
MCPS/v1 envelope codec. Scope/operation/IO/length/status validation, unknown commit
fail-closed, no raw protocol or wrapping key passed to C storage callbacks.
Seven real-C-fixture adapter tests added, including coordinator recovery paths.

This is a Rust composition + C storage seam, NOT a durable C session API.
PlatformKeyStore remains injected on Rust side. Callback memory safety, context
lifetime, atomic CAS/operation retention and authoritative reads are trusted host
contracts. No real platform secure store or disk backend was introduced.

Stage-three actual verification: 117 passed, 0 failed, 2 ignored with explicit
c-test-fixtures test feature; default-feature FFI 9/9 passed separately. Clippy
all-targets/all-features, standalone C consumer, MadObs header consumer and source
scan passed. Native fixture symbols absent from default static artifact; dynamic
public exports remain the same 15 madcrypto_* functions. C fixture feature must
not be enabled for distributed artifacts. See stage3 logs in docs/verification.

## Stage four

Independent Linux x86_64 host-development SDK packaging and relocated CMake
consumer validation are implemented. C and C++ apps link without other Mad SDKs;
MadObs is separately opt-in. Atomic no-replace output publication protects
existing targets including dangling symlinks and post-check collisions.
See docs/verification/STAGE4.md and docs/integration/standalone.md. Full host
suite remains 117 passed/2 ignored, and package-specific checks pass. Mobile
platforms, durable C sessions, hardware keystore and production release gates
remain incomplete. No binary publication or formal release performed.
