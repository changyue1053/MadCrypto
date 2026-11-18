# MadCrypto

Standalone Rust protocol kernel with a C ABI. **Stage-one development baseline,
not an audited production E2EE SDK.** No IMCore, IMSDK, MadDB, MadLink or MadObs
runtime dependency is required.

## Build and verify

Install Rust 1.100.0, a C compiler and platform build tools. Then:

```sh
cargo test --locked                         # core, primitives, FFI (no SQLCipher)
cargo test --workspace --locked --features madcrypto-ffi/c-test-fixtures # full host fixtures
cargo build -p madcrypto-ffi --locked
./scripts/verify.sh
# Optional header-only adapter verification:
MADOBS_INCLUDE_DIR=/path/to/MadObs/include ./scripts/verify.sh
```

Default public names: `madcrypto_core`, `madcrypto_prims`, `madcrypto_ffi`;
C header `crates/madcrypto-ffi/include/madcrypto.h`, symbols `madcrypto_*`.
`samples/c/main.c` is an independent C consumer. `madcrypto-store` is an
optional SQLCipher **reference transaction implementation**, not a MadDB bridge.
It builds native OpenSSL; default members deliberately do not require it.

## Delivered stage-one changes

- Retained source/tests and a separate local source-baseline commit.
- Renamed package/FFI identifiers without changing KDF labels, wire suite IDs,
  binary format, or serialized ratchet format.
- Unconsumed output rejects subsequent mutating FFI operations on that handle.
- Forged first-message authentication failure no longer consumes the OPK.
- Definite atomic-store commit failure leaves caller session state unchanged.
- Pending plaintext buffers are zeroized when consumed/freed; this does not
  guarantee wiping caller copies, OS memory, or every temporary in the kernel.
- NULL output probes never consume pending bytes, including empty plaintext.
- Optional bounded numeric observations; no callbacks under protocol locks.

## Scope and security limits

X3DH/Double Ratchet/Sender Keys and primitives are implemented; independent
protocol interoperability, side-channel review and third-party security audit
remain required. This is NOT a claim of compatibility with Signal wire formats.
ML-KEM/PQ, MLS and production national-crypto support are NOT provided.

**C sessions and identity handles are memory-only.** They are for integration
validation or explicitly nonpersistent sessions, not restart-safe product
identities. Rust consumers must provide the documented atomic SessionStore.
Production sender outbox atomicity, platform secure-store integration and a
MadCrypto–MadDB bridge are future work. No complete IM message pipeline is here.

See [PUBLIC_API.md](PUBLIC_API.md), [SECURITY.md](SECURITY.md),
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md), [TASK_RESULT.md](TASK_RESULT.md).
The retained [legacy README](docs/legacy-readme.md) is historical, not a support
or production-readiness claim. Source rights remain **Proprietary**; public
visibility does not make this an open-source-licensed package.

## Stage-two persistence development

`madcrypto_core::persistence` now supplies scoped `PlatformKeyStore` and
`AtomicSessionStore` ports plus `PersistentSession` trial/commit/recovery handling.
See [the contract and limitations](docs/security/platform-persistence.md).
Tests use real AES-GCM behind a software-only test provider; no actual mobile
secure-store adapter or production persistent backend is bundled.

## Stage-three C host storage seam

A Rust host can now compose `CStoreAdapter` with the stage-two coordinator and
Rust key provider. C callbacks store only encrypted envelopes and scoped metadata.
See [C storage adapter](docs/security/c-storage-adapter.md). This does not make
the existing `madcrypto_session_*` C handles persistent.

## Independent host development package

Build a relocated C/C++ SDK with `scripts/package_host.py /new/destination`;
consume using `find_package(MadCrypto CONFIG REQUIRED)` and
`MadCrypto::MadCrypto`. See [standalone integration](docs/integration/standalone.md).
Only Linux x86_64 is implemented and verified here, not mobile packaging or a
production binary release. MadObs is not required.
