# Explicit app-hosted iOS MadCrypto + MadObs evidence candidate

Public base: MadCrypto 80dacf2b9b6d5a2a0871da2a41a9a26968f406c1,
tree 1f422e7f1f4a961cd089d9b8e0c9a8af069e30e6. The local parent is tree
identical. No old SwiftPM lane, SDK code/ABI, policy, fixture, or dependency
was changed. The separate branch-only hosted workflow retains the standalone
OFF iOS package gates unchanged and requires OFF before ON.

ON starts from the same public binary producers. It independently installs
the same pinned null-provider MadObs runtime, builds the unchanged MadCrypto
XCFramework, extracts its simulator slice, and copies exact trusted archive
and header bytes into the named consumer. Producer outputs and install-staging
inputs are removed. The original hashed synthetic fixture and private-policy
bridge are reused. No credentials, payloads, endpoint, crypto storage or device
are involved. Original exact ABI and self-test expectations remain in the
XCTest methods, but call the installed SDK through app-private C entrypoints.

The independent UIKit host app target owns both static SDK implementations.
The unit-test target has only Swift test sources and its three-function private
header. TEST_HOST and BUNDLE_LOADER point exactly to the authored app. Linking
proof requires actual SDK/bridge definitions in the signed app and verifies
that the signed test bundle has none of those definitions and imports exactly
its three app bridge functions from the SDK namespace. Both real products must
be ARM64 Mach-O iOS Simulator and verify using ad-hoc signatures. No supplied
signing identity, upload, release, external service, or alternate package path.

Native project structure follows the explicit app/unit-test target, host and
loader patterns of the public MadDB iOS consumer and fixed exact product path
checks of the public MadInfer iOS qualifier. The named app and unit-test
bundle, executable and plist identifiers are authored here, not derived from
SwiftPM. Only the named top-level or app-embedded test product is eligible;
ambiguous layouts fail. The auto-generated xctestrun is a fingerprinted receipt
whose sole target and paths must match the signed products. It is never
dispatched. A separate canonical authored plan uses only exact app/test
paths and fixed host environment. No receipt environment/loader values are
copied. Both plans, product trees and installed input hashes are checked
around exact-manifest test-without-building on one job-owned simulator UUID.
The existing three exact named XCTest result assertions remain mandatory.

Five portable tests pass. The native project, linker export/import behavior and
the minimal authored app-hosted launch plan have NOT run with Xcode. In
particular the installed Xcode 26.2 XCTest launcher may require additional
exact stock loader metadata; only a real pinned run can establish that. Review
the exact tree before leasing a single named branch/CI run. Do not publish an
artifact or describe this as native evidence from local tests.

## Link-failure classification only

Exact public ebddf9d11f87d6c51ef6ea283665345a7eb7949e, run 44674213211,
passed OFF; ON stopped with undefined-symbol during Ld. That category alone
does not prove whether the app linker or test bundle linker failed. This
candidate changes only the private output classifier of failed consumer-link
commands. It requires the fixed Xcode failed-command summary and one complete
Darwin undefined-symbol block; then classifies the failed link as app/test/
unknown, bridge exact-three as all/partial/none, and other symbols as a fixed
SDK/system-like/unknown/mixed namespace class with a coarse distinct count.
No full symbols, stack paths, raw lines, or arbitrary names are emitted.
Malformed/multiple/incomplete or over-budget inputs are inconclusive results.
The parser inspects at most 8 MiB, 20,000 bounded records, and 8 KiB per line.
Nine portable tests pass; no native run and no flags or acceptance gates changed.
