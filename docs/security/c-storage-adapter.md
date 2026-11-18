# Stage three: C encrypted-store adapter (not a durable C session API)

`madcrypto_ffi::store_adapter::CStoreAdapter` implements the Rust
`AtomicSessionStore` trait using the v1 callbacks in `madcrypto_store.h`.
A Rust composition layer constructs the adapter and injects a Rust
`PlatformKeyStore` into `PersistentSession`. C host callbacks receive ONLY
scoped metadata and encrypted state/effect envelopes. No plaintext ratchet,
identity private key, wrapping key or decrypted application effect is passed to
these storage callbacks.

```
Rust PersistentSession + Rust PlatformKeyStore
                 | encrypted envelope + CAS metadata
             CStoreAdapter
                 | synchronous C callbacks
      trusted host atomic database implementation
```

The existing exported `madcrypto_session_*` handles are still memory-only. This
stage does not wire them to persistent state, implement identity/prekey recovery,
provide a Keychain/Keystore/HUKS adapter, or add a MadDB dependency. The C fixture
is in-memory test code, not a production database implementation.

The adapter itself does not encrypt. Direct callers of its AtomicSessionStore
trait must supply already-sealed records; public SealedCommit bytes are not a
cryptographic proof. Use PersistentSession to establish this ordering. The
trusted host must not manually put plaintext or raw key bytes into those fields.

## ABI and ownership

- `struct_size`, ABI=1, context and required load/commit callback pointers.
- Constructor is unsafe: the host must maintain context/functions for the entire
  adapter lifetime. Adapter does not free context. Drop adapter before context.
- Adapter is intentionally !Send/!Sync; callbacks execute synchronously on caller
  thread, not under a legacy FFI registry lock. No concurrent deregistration,
  reentrant calls into the same adapter, exception/longjmp/unwind across C.
- Buffers are borrowed for the callback. Host may copy, never retain pointers.
- Scope is binary length-prefixed app/account/session; not a filesystem path.
- A trusted host callback can violate memory safety if it ignores capacity. This
  interface validates lengths/statuses, but is not an untrusted-plugin sandbox.

## Load protocol

First callback probes length; second fills the caller-owned buffer. Both calls
must distinguish absence from IO error. The read buffer is bounded to 2 MiB plus
2048 bytes of framing. Each encrypted state/effect field is <=1 MiB, text metadata
is <=128 bytes, framing/trailing bytes/UTF-8/versions/revision are checked.

If a concurrent update changes length, callback must never overrun capacity;
return error rather than truncated success. A vanished record on the second read
is an error, not an empty session. A newer complete record is acceptable only if
it is an authoritative committed snapshot; core revision CAS handles writers.

The MCPS/v1 envelope is a persistence framing format, not the messaging wire
protocol. Its encrypted fields are authenticated by the Rust key provider on
load/recovery; the framing parser itself does not decrypt or authenticate.

## Commit protocol

Host must atomically compare expected revision and retain unique operation id
with BOTH latest session envelope and operation envelope. has_expected=0 means
insert-only, revision increments exactly once. Codes: Committed=0, Conflict=1,
Rejected(no-write)=2, Unknown=3. Any unfamiliar code maps to Unknown, never success
or definite rejection. Core freezes its instance before invoking commit and
reconciles an uncertain outcome through authoritative operation lookup/reload.

Host must retain operation records until application acknowledgement. Backend
power-loss guarantees, recovery, account authorization, nonce discipline and
antirollback remain the host contracts described in platform-persistence.md.

## Verification

Tests compile a real C fixture with the public header, then exercise Rust→C→Rust
storage roundtrips, CAS/duplicate operations, cross-scope reads, oversized probes,
IO failure, vanished/truncated/corrupt reads, unknown codes, envelope truncation
and mutation, coordinator Unknown with/without write and encrypted effect recovery.
The AES provider in coordinator tests is test-only; no native platform support or
external audit is inferred from these host tests.

Native test fixtures compile only with explicit `c-test-fixtures`; do not enable
that feature for distributed binaries. verify.sh tests with fixtures then builds
the default production-shaped native artifact without them.
