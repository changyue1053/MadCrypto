# Stage-two verification — host scope only

Adds Rust-only scoped key-store/persistence contracts; no new third-party
runtime dependency, native platform provider or C durability change.

13 targeted tests cover: encrypted state/effect reload and continuation; locked
key and definite failure leave live state unchanged; ambiguous commit freezes
and recovers; stale writer CAS and duplicate operation conflict; scope/revision/
ciphertext/alias/role tampering; deleted key and IO failure distinct from missing;
hardware requirement rejected by software-only test provider; invalid identifiers;
oversized effects and protocol errors; host panic after durable write.

The software test key is deterministic fixture material and provider RNG is
seeded only for repeatable testing. This is NOT a production key, provider, or
antirollback implementation. Device/key hardware/true crash tests are not run.
Additional sender test proves Unknown recovery returns the identical persisted
ciphertext and a reloaded sender advances the message counter exactly once;
a no-write Unknown branch requires reload before retry. These are atomic-store
contract tests, not a complete application outbox or network exactly-once claim.
Original two SM2 stress tests remain ignored (unrelated experimental suite).

See stage2-host.log and stage2-focused.log for actual commands/results. Full
workspace tests, Clippy, standalone C and optional MadObs header sink are rerun
for this stage. No external audit or security certification is claimed.
