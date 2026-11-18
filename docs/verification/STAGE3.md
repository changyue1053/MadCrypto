# Stage-three C encrypted-store seam — host verification

Seven storage-adapter tests use a real C callback fixture compiled against
madcrypto_store.h and linked with the Rust FFI crate. Tests cover CAS/duplicate
operations, retained operation reads, cross-scope absence, IO errors, oversized
probes, zero/oversized actual length, probe/read growth, vanished/corrupt reads,
unknown status fail-closed, revision overflow, bounded/truncated/mutated envelope
parser, and coordinator Unknown(write/no-write)/Rejected outcomes.

The actual>capacity test returns an invalid length without writing past capacity;
the test does not intentionally invoke C memory-unsafe behavior. Untrusted
callbacks can still corrupt memory; valid callback memory/lifetime behavior is
an explicit unsafe-constructor contract.

Coordinator tests use AES-GCM in a test-only Rust provider. Only sealed envelopes
and metadata are sent to C, and recovered effects are decrypted in Rust. This is
not an OS key-store adapter, disk durability certification or durable exported
C session API. Existing C session handles remain memory-only.

Independent review found no blocking issue within trusted host contracts; its
additional oversized-read/growth/definite-rejection suggestions were implemented.
No external cryptographic/security audit is claimed.
