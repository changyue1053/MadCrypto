# Separate direct iOS app runtime qualification candidate

Public base 74d85d64455f881e7650ac19cddd8348e4605ccd (tree
c774a080054583764d5fbf07127d5d47b5b15d03) proved that the standalone signed
simulator app links both exact installed SDKs. This branch-only smoke candidate
uses the same native app target and flags, installed archive and header pins,
null-provider policy path, public synthetic fixture, observation bridge, and
private C wrappers. Only the test variant's UIKit delegate changes; no shipping
SDK or observable end-user data is added. Existing standalone OFF, SwiftPM
and app-hosted XCTest lanes remain unchanged and must be reported separately.

The new delegate directly evaluates the existing exact ABI version, SDK
self-test and synthetic private-drain success assertions. It publishes one
small JSON receipt with those three exact case names and boolean outcomes, the
launch challenge, and its process ID. It writes an exclusive mode-0600
temporary file and publishes it via a same-directory atomic, non-overwriting
hard link. Zero runtime outbound endpoints, no real crypto inputs and no
telemetry payload, network output, or archives are accepted as results.

The runner verifies exact Xcode and SDK versions, creates one fresh simulator,
installs only its verified signed ARM64 simulator app, and binds the signed
installed bundle identity to the built app byte tree. It checks the fresh
owned app/data containers and absence of all expected receipt/work files
before launch. A fresh random 128-bit nonce is delivered as the sole app
argument, and the exact simctl app-ID/PID output must match the strict receipt.
A bounded final-file-only read, post-termination immutable receipt check,
reverified app signature/identity and both app/input/fixture fingerprints are
required. Duplicate/extra keys, non-boolean outcomes, stale nonce, mismatched
PID, aliased/outside paths, or changed artifacts fail. Outputs contain only
fixed labels, not process IDs, nonces, paths or receipt data. No release,
artifact upload, device use, JNI, third-party telemetry, or new downloader.

This is a direct App runtime smoke test, not a substitute for either XCTest
lane or evidence that their link or launch blockers are resolved. Five
portable tests and supporting source checks pass. The UIKit process, exact
simctl layout/output, receipt publication, installed signing identity, and
other macOS-specific behavior remain unverified until a scoped hosted run
is separately reviewed and authorized.

## Container evidence after the first hosted run

Run 44717049978 on public bff1ca96 proved the signed/link gate and reported
direct-container. In that exact source the label belongs to the bounded
simctl get_app_container invocation; Python path validation failures were
mapped separately to direct-receipt-or-artifact. A normal macOS path alias
cannot explain the logged label by itself. The original label cannot
distinguish app vs. data or the query's surrounding phase.

Only bounded fixed diagnostics change here: initial, prelaunch or postrun,
app or data, query vs. path. No raw output, returned path, ID or filename is
printed. The runner's fresh simulator, exact canonical container policy,
signed executable and before/after fixed source, fixture, archive and receipt
identity are unchanged. The nonce and PID are a freshness binding in the
trusted job, not cryptographic remote attestation or protection against a
malicious actor controlling that job. No alternative alias is authorized by
the available evidence. Six direct and eight supporting portable tests pass.

## Fixed simulator install diagnostics

Public 7a99d90c106c4ef933f94aee1c959d1789c59da2, run 44718590237 and job
136228192995, proved the signed-link check but failed direct-app-install
before container lookup. This additive diagnostic preserves the exact
install argv and 90-second deadline. It reads at most 64 KiB, captures
no persistent logs, and distinguishes start, timeout, signal, cap and generic
nonzero. For a nonzero exit, anchored Apple outer/underlying records map
to short fixed allowlisted installer/CoreSimulator domains and code sets.
Unknown codes/domains and ambiguous records get generic buckets. Code
numbers are observations, not a root-cause claim inferred from message text.

No path, app metadata, raw message or unknown code is emitted. On install
success, the original app identity, container, launch, receipt, verification
and cleanup gates all still run. No retries, plist/signing changes or new
external action. Three diagnostic tests cover synthetic simctl records and
actual portable local timeout/signal/limit/start paths.

### Timing evidence, not a new install policy

In run 44720991668 at public 37f2f42fde53f1465259532f4b8bf2995284deba,
Python's buffered signed-app and timeout lines appeared about 10 ms apart.
They were delivered on stdout flush, not measured command timestamps. The
runner now flushes signed-build, install-start and install-outcome boundaries
immediately, including before cleanup on failure. This changes no argv,
timeout, retries, signature, receipt, or app acceptance rule.

Separately, an empty or interrupted selector wakeup cannot prove the deadline
expired; recheck monotonic time before treating it as timeout. Real portable
child tests close stdout and stderr before a delayed success/nonzero exit and
cover a genuine deadline. An early-empty/interrupted-wakeup injection uses a
real child to validate that the portable runner waits rather than timing out.
The exact hosted install duration and cause are still unverified.

### Optional same-host installer comparison

The separate checkpoint/madcrypto-ios-obs-install-control workflow uses the
opt-in --with-install-control mode. The normal direct workflow and all
standalone/XCTest gates are unchanged. Only after an attempted product
install and successful cleanup of its owned simulator, a second fresh owned
iPhone-16 simulator on the same runner and pinned runtime is used once.

The small control has only a public synthetic UIKit delegate and distinct
bundle ID, retaining the product test target's base platform and signature
settings. No fixture, SDK header/archive/provider or bridge is copied.
ARM64 simulator, exact app identity, valid signature and absence of SDK
definitions are required before its single install. It is never launched.
It uses the same 90-second / 64 KiB install wrapper, a six-minute control
work limit, and independent bounded shutdown/deletion. Setup or cleanup
failure is inconclusive, not an install result. No logs or binaries upload.
No retries are performed.

Only fixed comparison labels are emitted, distinguishing both install,
both timeout, just one install, neither install, or inconclusive. Product
still runs and verifies its own receipt on its existing gates; the control
cannot satisfy a product or SDK runtime assertion. Install-only comparison
is sequential, can be affected by shared service state, and does not prove
causality for differences. No Xcode/simulator run on this candidate; 22
portable tests pass.
