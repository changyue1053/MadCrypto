# Nonshipping optional iOS observer consumer source candidate

Public MadCrypto parent: 2739b6bd88f5e72495337ccde7ea143e4d1dc91a,
tree b056f861d1ccf3d924bb8ab1d60ddd5384783fc4.
Public MadObs required runtime pin: 4af77ffa464a48307e5ff2d95f10b835919d205b,
tree 3a03801beb18c9601630cc4421b95c2743018dfb.
The runtime/observer/privacy declarations were inspected from that exact public
tree already present locally. No historical gated artifacts are inputs.

This directory adds no shipping targets, default dependency, public ABI,
key/protocol behavior or other platform changes. A dedicated workflow and Swift consumer candidate now exist, but are not evidence
of successful native compilation or runtime execution.

## Fixture contract

prepare.py accepts only tests/obs_adapter.c SHA256
4e355fb95a055883596ddc36d43ea58dd5d261a8e540bf20275d72db07fe7c88.
It generates a new file exclusively, never overwrites. It adds an NDEBUG rejection,
a bridge declaration, renames main for test invocation, and inserts exactly one
forwarding assertion after the original callback's validation. Every fixture
operation, existing assertion and cleanup stays byte-identical. The original
public adapter is unchanged. No fake poll or hand-built replacement event is used.

The fixture has existing synthetic ephemeral operations and fixed one-byte
inputs. It produces exactly one numeric encrypt-completion event. No real account,
credentials, endpoint, production traffic or crypto persistence is involved.

Bridge.cpp permits only the exact fixed event table, including zero unused
attribute slots; it preserves the original event and uses the pinned madobs_sanitize_event policy
to construct a bounded compact copy with exact timing removed and no attributes.
The copy is checked again for exact sanctioned IDs/version, zero timestamp,
reserved field and attribute slots before admission through madobs_emit_generic_event
and requires MADOBS_OK, not the void callback's invocation result. One invocation
per process is enforced. Assertions remain active; a fixture failure aborts the
isolated test process rather than continuing with a partial success.

The runtime uses a unique disposable local observer directory supplied by the
future XCTest harness, a null crypto provider installation, and a local discard
sink. Observer WAL and batch metadata may exist temporarily; this is not a
zero-filesystem-side-effect test. No crypto session material is sent to it.
Sink batches must satisfy the exact single-event, zero-attribute privacy policy,
with at most four callbacks and at most 1 MiB each. No bytes are logged or retained
by the sink. Stop precedes counter inspection and destroy. Success requires one
admitted, one enqueued, one drained and zero queue/WAL drops or rejected batches.
Shutdown failure returns failure and retains callback state to avoid freeing a
possibly live callback context. A future isolated process harness must bound total
runtime and remove its own temporary directory after the process exits.

## Independent qualification orchestration candidate (not executed)

Preserve the original default iOS ABI/version and existing-selftest gates. ON
qualification must consume separately installed and relocated ARM64 simulator
MadCrypto XCFramework and exact MadObs static runtime, with producer directories
removed and no source-target fallback. Compile generated fixture as C with asserts
enabled, bridge as C++, and call qualification exactly once from a dedicated
XCTest. Keep the existing ABI/selftest expectations unchanged. Require explicit
ARM64 simulator evidence and exact named XCTest result; unsigned device linking
would not establish device runtime. No implementation, signing, uploads or hosted
execution is part of this source-only checkpoint.

## Local validation

python3 ios-obs-consumer/test_prepare.py: four tests pass, including reversible
transformation and mutated/empty fixture rejection. The fourth test checks malformed-input guards and sanitize-before-admit ordering
in source; it does not execute the sanitizer or establish runtime behavior.
These are source tests only;
Apple toolchain/native package composition and real runtime admission/drain are
not tested on this Linux host. No downloads, SDK installs or remote writes.


## Orchestration scope and limitations

The dedicated workflow runs the original OFF preparation/build/simulator scripts
unchanged in one job. ON uses the same original preparation and package build,
copies the unchanged two original Swift tests and Consumer implementation, and
adds one named fixture test. The third test is simulator-only. MadObs's separate
public source fetch is anonymous, exact commit/tree/origin checked, with isolated
Git config/home. No credentials are persisted. Dependency preparation precedes
native builds; Rust uses the original offline build, Swift consumes local binary
targets with automatic package resolution disabled. This is not a network sandbox.

Preinstalled CMake follows the approved MadObs recipe without installing or pinning
a replacement. Xcode/SDK26.2 and target SDK zlib remain mandatory. The simulator-only
static MadObs install is relocated, producer/build directories removed, wrapped as
a local XCFramework, and its staging prefix removed before consumption. MadCrypto's
actual XCFramework is moved into the same independent package and Rust outputs
removed. No producer source target is a Swift dependency. No fallback is provided
for unexpected install, package or XCTest binary layout.

New orchestration runs Python in isolated mode to avoid local stdlib shadowing.
The job temp root must be a nonsymlink directory and subprocess output is captured
with fixed failure labels. Every subprocess has a timeout; returned output is
bounded, though temporary log growth during a subprocess is not hard-capped.
Only a newly created UUID is booted/tested/shut down/deleted. ON asserts ARM64 in
Swift and inspects the actual built XCTest binary before test-without-building
against the same UUID. The exact three named pass results are required. Cleanup
attempts both shutdown and deletion with finite timeouts.

OFF retains its historical unsigned device link and simulator ad-hoc signing.
ON has no device build or device execution, only simulator ad-hoc signing using
no supplied identity. There are no uploads or releases. Running original OFF
scripts does not imply their behavior has been broadened or rewritten here.

Local checks: four fixture source tests and three orchestration/result parser
tests pass; new Python modules compile to bytecode. No native compilation, Swift
package evaluation, hosted workflow, simulator or private runtime test has run.
A fresh installed runtime may still expose toolchain/Swift module or layout
incompatibilities, which must fail closed rather than altering production code.

### Reviewed artifact-binding and failure-cleanup correction

The bridge target already explicitly links `z` and `c++`; a new regression test
locks that transitive-library requirement. Swift removes its local observer WAL
only after verified status 1 and propagates any removal error as a test failure.
On qualification failure it leaves the directory alone until whole job-owned
simulator/process teardown, respecting retained live bridge callback state.

After build-for-testing, the orchestrator now requires exactly one top-level
.xctestrun manifest and exactly one contained TestBundlePath resolving to
Debug-iphonesimulator/MadCryptoPackageCheckPackageTests.xctest. Other SwiftPM
launcher/layout variants are deliberately unsupported and fail with a fixed
built-artifact-binding diagnostic. The original successful baseline discovers
its scheme itself and provides no checked-in xctestrun sample, so this expected
manifest layout has only synthetic validation, not demonstrated hosted evidence.

The actual linked test executable must define the fixture entry, session encrypt,
bridge forwarding/qualification, and MadObs admission/private-batch/stats/stop
symbols according to Apple nm -U -j (defined symbols, not dynamic imports).
Static-inline adapter/sanitizer symbols are not required because inlining may
legitimately remove them. Before execution, the complete products tree including
manifest and bundle code-signature files is fingerprinted. The exact manifest is
passed to test-without-building on the same UUID; its selection and the entire
fingerprint must remain identical afterward. Symlinks escaping products fail.
This is artifact identity evidence, not cryptographic attestation of a signer.

Eleven portable tests now pass, including missing/duplicate/escaping manifests,
signature-file hash mutation, required defined-symbol omissions, explicit zlib,
failure cleanup and exact success-label class. No native or hosted run occurred.

### Manifest execution contract hardening

The parser now explicitly supports one target in format 1 or one enabled
configuration/target in format 2, with a closed target field set. It rejects
UI/app-hosted/destination-artifact modes, skip/only filters, arguments, arbitrary
environment overrides, alternate hosts, unknown execution fields and external
DependentProductPaths. Only two exact optional TestingEnvironmentVariables are
recognized: the fixed products plus pinned platform framework/library search
paths. Injected loaders, XCInjectBundleInto and other variants fail closed; no
unproven loader exceptions were added.

Only the explicit framework-test facility
__PLATFORMS__/iPhoneSimulator.platform/Developer/Library/Xcode/Agents/xctest
is eligible. It must be an existing regular canonical file under the fixed
Xcode26.2 Platforms directory, and its bytes are included in the before/after
snapshot. This is an intentionally narrow candidate facility, NOT a claim that
this exact Xcode SwiftPM-generated manifest has been observed. Unsupported
host/layout/environment metadata fails built-artifact-binding for later review.
There is no broad fallback or inferred application host.

Apple TN2339 documents build-for-testing and passing the resulting xctestrun
explicitly to test-without-building, including TestHostPath/TestBundlePath:
https://developer.apple.com/library/archive/technotes/tn2339/_index.html
It does not establish the exact SwiftPM manifest emitted by Xcode26.2 here.
The checked-in baseline has no such generated manifest to inspect locally.

Twelve portable tests pass, including explicit target/environment/loader/filters/
external-product rejection. Fixture expected paths are resolved before comparison
so macOS temporary-directory aliases do not create false test mismatches.
No native tests or hosted execution were run.

### First hosted ON link failure: diagnostic-only successor

Public 91f058346e948e782bd0f5bfa44d8e553a44eb7e has tree
e8e51270f223efd9f0c50a41ec37b94dd9adf2e0, identical to the local parent
217c5c7773e260eea3e93e10750b7b731c0faef0. Reported run44612605998 passed OFF
but ON failed consumer-link before test execution. That fixed label does not
establish whether the underlying error was a header/module, compile, linker,
platform or signing issue. No raw hosted logs were read for this change.

Only a failing consumer-link subprocess now classifies bounded captured diagnostic
bytes. At most 1 MiB (head/tail for larger output) is inspected. The output is
one fixed category: header-missing, module-definition, module-import,
undefined-symbol, duplicate-symbol, library-missing, platform-mismatch, signing,
package-resolution, swift-compile, c-compile or other. Timeout is separate.
No captured line, path, identifier or arbitrary text is emitted. Categories are
heuristic triage, not a root-cause proof; unknown output fails other. All build,
privacy, manifest, symbol, identity and result gates remain unchanged.

Sixteen portable tests pass. Neither clang nor Swift is available on this Linux
host PATH, so Apple module import was not reproduced. No downloads, native builds,
hosted execution or remote changes were performed for this successor.

### Bounded phase diagnostics after consumer-link-other

Reported public diagnostics head 5f97e3611a4096c5ae805ecb5d90957bf12dfbc6,
run44620696754: OFF passed; ON returned nonzero with consumer-link-other.
No deterministic source-level cause is established, so this remains diagnostic-only.
The failed-command log is now scanned sequentially with hard analysis limits:
8 MiB total bytes, 20,000 bounded reads, 8 KiB per line fragment. Overlong lines
are discarded without interpreting their fragments. The diagnostic reports whether
the scan was complete or truncated; unknown complete output is distinguishable
from unseen output. These are scan bounds, not a hard cap on subprocess temp-file
size while Xcode runs.

A fixed command-phase allowlist records the last observed package/preparation,
dependency scan, C/Swift compile, linker or signing phase. That is contextual,
not proof of which phase caused failure. Fixed early-error categories distinguish
binary artifacts, package products/targets, build locks, destinations and build
preparation, with generic xcode-error as fallback. No raw command, path, symbol,
error line or arbitrary substring is printed. All positive gates remain unchanged.
Twenty portable tests pass, including middle-of-log detection, truncated scans,
overlong-line injection rejection, line-count exhaustion and fixed phase outputs.

### Destination bucket correction and independent discriminants

Reported run44629874786 at public633fea38ab7c269e3c4244cfa3450b23de23013c
returned consumer-link-destination-phase-prepare-complete. The old heuristic
matched any occurrence of simulator, including file paths, so this is NOT proof
that the job-owned destination was invalid. The new classifier requires explicit
eligibility error phrases and distinguishes missing SDKs, test-action configuration,
multiple build producers and missing build inputs. Paths alone map to xcode-error.

Compared with the unchanged successful OFF simulator script, ON retains the same
scheme, exact UUID destination, ARM64/only-active settings and simulator ad-hoc
signing options. Its deliberate differences are build-for-testing followed by an
exact-manifest test-without-building and disabled automatic package resolution.
No speculative changes to those gates or production link flags were made.

Before consumer compilation, both actual installed XCFramework Info.plists must
have exactly one ios/simulator slice, exactly arm64, and contained archive/header
paths. The selected actual archives must independently pass lipo arm64. A separate
xcodebuild -showdestinations query must identify the exact owned UUID once in the
eligible section with platform iOS Simulator and arch arm64. Unexpected formatting
fails fixed consumer-destination-eligibility rather than guessing a destination.
These checks distinguish package metadata/architecture and scheme eligibility
from the subsequent link failure. They are additive, not a build success claim.
Twenty-three portable tests pass; no new native or hosted execution occurred.
