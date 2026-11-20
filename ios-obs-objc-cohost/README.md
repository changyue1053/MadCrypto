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
