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
