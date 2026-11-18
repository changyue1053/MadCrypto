# Unreleased

Stage-one independent MadCrypto naming and host validation; pending ownership,
prekey authentication ordering, rollback-safe receive, optional numeric observation.
Rust ResponderKeys OPK is borrowed instead of moved. No intentional wire/KDF/schema
change. No formal release, package publication or stability promise.

Compatibility tightening: C initiate/accept now reject authentic no-OPK flows,
which the legacy IMCrypto facade accepted. C plaintext limits and wrong-type
free errors are now enforced. Mad public namespace is new; wire format is not
changed. Rust low-level no-OPK remains available with host persistent replay
protection responsibility. No claim of source/behavior compatibility with all
legacy FFI clients is made.

Stage two (unreleased): scoped platform key-store port, authenticated session
state/effect envelope, Result-based storage reads, CAS and unknown-commit recovery
barrier. Rust-only; no new platform support or C persistence claim.

Stage three (unreleased): versioned C encrypted-store callback contract, bounded
persistence envelope codec and thread-affine Rust CStoreAdapter. Unknown host
commit statuses fail closed; no plaintext keys cross storage callbacks. Existing
C session handles remain memory-only; no mobile/provider claim is introduced.

## Stage four: independent host development packaging

- Add clean no-test-feature static package, relocatable CMake imported target and
  SHA-256 inventory with toolchain/source provenance.
- Add independent C/C++ app builds, parallel-process smoke, wrong-platform and
  overwrite rejection, and optional MadObs package-consumer verification.
- Linux x86_64 only; no mobile packaging, device secure-store implementation or
  production binary redistribution approval. C ABI/wire remain unchanged.
