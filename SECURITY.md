# Security status and disclosure

This development snapshot has not passed an independent cryptographic audit.
Report suspected vulnerabilities privately to the repository owner; do not post
keys, plaintext, credentials, or private production traces in public issues.

Current threat boundaries: trusted in-process caller, valid FFI pointers,
cryptographically secure platform entropy, secure tenant-scoped storage supplied
by host, authenticated identity/trust policy supplied by host. Native memory
corruption, malicious in-process clients, disk rollback attacks, side channels
and compromised OS are not solved by the handle API.

Release gates: independent protocol review/interoperability, FFI fuzz/sanitizers,
platform key-store and recovery contracts, sender state/outbox atomicity,
resource quotas/input limits, global registry isolation/poisoning policy,
all secret-temporary zeroization audit, license/NOTICE completion, native binary
dependency coexistence and supported-device validation. Never market this source
snapshot as production-ready or post-quantum secure.
