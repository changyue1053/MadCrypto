# MadCrypto app-owned Objective-C cohost candidate

Baseline public fc297e78fb50a39b538673fe6afca5c13d1ddc7d, tree
55609bc5f6f65a7ba65321f637c7cb52f63f2b5e. The producer recipes, independent
installed MadCrypto/Obs archives and headers, Obs commit/tree, fixture digest,
null-provider private bridge, ABI expectations and all original lanes are
unchanged. This candidate changes only the fixture composition. The exact
three prior cases still require ABI 0.1.0, SDK self-test success, and the
private sanitized synthetic fixture's original exact local runtime proof.
No real credentials, transport, network endpoints, JNI, product ABI or
non-iOS targets. No upload.

Observed known-good architectural precedent: MadDB public 951ed05a210a2e722edf79fc6f5a6cd8acbd53b8,
run 44760643429. It uses an Objective-C++ XCTest bundle with no SDK linkage,
one app-owned Objective-C class through BUNDLE_LOADER, and
ENABLE_DEBUG_DYLIB=NO for both native build and test actions. This differs from
MadCrypto's earlier Swift XCTest three-C-symbol route and from direct simctl
installation/lookup (which failed before runtime); it does not establish the
cause of either earlier failure.

Only the disposable app target owns the two SDK implementations and the
original C fixture. XCTest imports one named Objective-C app driver, without
SDK names, SDK load commands, or linked copies. The previously brittle
standalone three-symbol export-file restriction is not used in this test app;
the shipped SDK's exports are untouched. Both native phases use the same
frozen generated products and exact owned Simulator UUID, without direct
simctl install or container lookup. Generated receipt validation checks
exact host/test paths, IDs, known dependency/loader/environment limits,
no UI/alternate target, no test filtering and no arbitrary override.
Only the one canonical, validated generated xctestrun is passed explicitly
by -xctestrun to test-without-building; no scheme rediscovery or alternate
resolution. ENABLE_DEBUG_DYLIB=NO is a build setting locked in the authored
project and build argv; the prebuilt test action cannot rebuild it, and both
consumed products prove ownership and reject .debug.dylib dependencies.
The receipt and complete products tree are hashed before/after. Every
candidate known app/test bundle needs independent ad-hoc signature,
ARM64 simulator platform and symbol/linkage verification. Existing exact
three-test result parser is unchanged. All package/fixture hashes rechecked.
No raw logs or paths emitted.

Dedicated stock Apple checkpoint only; generic Linux host push is excluded
for this literal branch while preserving tags/other branches, PRs, and all
existing jobs. Existing standalone OFF is mandatory before ON.

Fifteen portable source/fixture tests pass; Objective-C/Xcode native build,
receipt shape and actual runtime remain unverified for this exact candidate.
Do not claim the successful MadDB result as MadCrypto evidence. No CI or
remote push performed locally.

Generated Apple metadata trust boundary: the input is one fresh receipt from
the exact pinned local Xcode in a disposable directory for our own authored
project, never an external manifest. Known launch/selection overrides are
checked at root, configuration and target levels; test paths, dependency
closure and recognized scheme/loader values remain exact. Opaque Apple-generated
metadata not consumed by these checks is trusted as tool output, not claimed
to be exhaustively parsed or excluded from Xcode semantics. No arbitrary
external receipt, filename fallback, discovery or reconfiguration is supported.

### Separate build-only App export evidence

Based on public 14ffaac924eaaf8b46e8413a94006eb336514d29, tree
035469a136a0837875d949d711ec446154e3021f. Run 44766500496 ON passed the
installed slices, then failed undefined symbol in an ambiguous link block.
This independent branch-only evidence job reuses the identical pinned preflight,
sources and archives and strips XCTest from the disposable native build graph.
The actual App target settings, sources, archive identities, explicit stock
Xcode/key build options and destination remain those of the cohost.
One owned eligible simulator is created for the same destination, but
never booted; no XCTest build, no install, no launch, no second native run.

The App executable must be signed and proven ARM64 iOS Simulator with exact
bundle identity, no SDK/debug-dylib loads, unchanged source/input and bundle
hashes. Before invoking Apple's dyld_info -exports, require an actual,
nonempty, bounded Mach-O dyld export-trie command/range. This avoids the
symbol-table fallback documented by the tool implementation:
https://github.com/apple-oss-distributions/dyld/blob/main/other-tools/dyld_info.cpp
Only exact local regular-address App driver class/metaclass entries can
satisfy the result. Missing, ambiguous, malformed output or unsupported
tool behavior fails closed. No names, paths, or raw output emitted.
A positive establishes App driver exports in this App build, not XCTest
loader correctness or runtime acceptance. The original cohost lane is
unchanged when the explicit branch-only mode flag is absent. No local
Xcode build or remote action; nineteen portable tests pass.

### Minimal App-only driver surface correction

Public b0c34468d05b5117248f0849f07137059c2ff48e, run 44770161077
job 136405358183, proved the signed isolated App but reported neither
driver class nor metaclass in the real export table. This successor gives
the fixture driver declaration explicit default visibility and lists only
its two Objective-C symbols in the disposable App's EXPORTED_SYMBOLS_FILE.
The XCTest target gets no export setting, retains BUNDLE_LOADER, and
still cannot link or import the actual SDK implementations directly.
No blanket ENABLE_TESTABILITY/visibility change and no SDK ABI changes.

The regular ON route now checks both exact local driver symbols in the
verified App's actual dyld export trie before test execution and at the
same immutable post-test check, and rejects exported SDK/bridge prefixes.
The existing signature, owned UUID, artifact identities, validated exact
xctestrun, no-duplicate-linkage and original three result checks are still
mandatory. This addresses the observed standalone export defect; it does
not prove XCTest linkage or rule out other hosted blockers until the exact
candidate is reviewed and run. Twenty portable tests pass.

For a review-approved diagnosis without test execution, use
`python3 -I ios-obs-objc-cohost/run.py --receipt-evidence-only` after the
existing pinned preflight. This builds the same consumer graph with actual
relocated installed SDKs, using a fresh eligible simulator that is never booted
and is deleted on exit. It does not execute XCTest. The unchanged policy
must still pass for the evidence-only command to succeed. On policy failure,
the command emits finite reason labels from the validator and does not expose,
upload or execute the receipt. A documented schema example or third-party
synthetic receipt is not evidence of what the pinned runner emitted.
