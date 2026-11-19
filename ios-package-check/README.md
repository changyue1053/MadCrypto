# iOS package-integration validation candidate

This separate check starts from public MadCrypto commit
`57b7431931ff2128c9e7955509bb199d141f9534`. It changes no crypto implementation,
public ABI, selftest, dependency lock, license, host checks or persistence code.
It does not use earlier blocked work. It adds no application or new algorithms.

## Proposed gates

- Rust 1.100.0, Xcode 26.2 (17C52), SDK/runtime 26.2, Apple Silicon host.
- Compile `madcrypto-ffi` with no features for aarch64-apple-ios and
  aarch64-apple-ios-sim, deployment target iOS 16. No SQLCipher/OpenSSL store,
  optional MadObs, test-fixture exports or key-handling changes.
- Official `xcodebuild -create-xcframework` packages static archives and the
  unchanged C header/module map. Verify slice identities, ARM64, public symbols,
  absent debug fixtures and unchanged license/header bytes. Static archives
  also contain Rust dependency symbols; no symbol-hiding claim is made.
- Copy only the final binary package into a separate Swift package consumer.
  No producer Rust sources are dependencies of the consumer. Build that package
  for generic iOS without signing, then run its two named XCTest cases on an
  isolated job-owned ARM64 iOS simulator: ABI 0.1.0 and the existing exported
  `madcrypto_selftest()`. No app target, user input or secret fixture is added.
- Require successful xcodebuild plus xcresult exact named passes, zero failures
  and zero skips. Raw logs stay local, no artifact upload or release.

The existing selftest uses fixed synthetic data internally. It exercises existing
protocol round trips/rejection checks, NOT the Rust RFC known-answer test file.
Host known-answer tests stay in the existing Linux workflow. Simulator success
would prove package integration and that selftest on the simulator, not a
cryptographic audit, interoperability, secure storage, device execution or
production E2EE readiness. iOS 16 is a build minimum, not an executed OS matrix.

## Execution status and licensing

Only synthetic parser/static source checks have run locally. Rust and Apple tools
are unavailable in the current local environment. Swift package scheme discovery,
static linking, actual archive platform compatibility and simulator execution must
be verified by the proposed hosted job; they are not reported as passed.

This is a development-only local package check. Original Proprietary LICENSE and
THIRD_PARTY.md remain unchanged. Included notices are not a complete transitive
license audit. No redistribution/public binary permission or license change is
implied. No binary publishing step exists.

Reference patterns: Apple's “Creating a multiplatform binary framework bundle”
and “Distributing binary frameworks as Swift packages” documentation:
https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle
https://developer.apple.com/documentation/xcode/distributing-binary-frameworks-as-swift-packages

Preflight reports independent fixed labels for architecture, Xcode, pinned Rust
installation, Rust targets, locked dependency fetch and synthetic format tests.
Failure output remains local. The inspector uses a non-standard-library module
name to avoid shadowing Python's `inspect`; synthetic checks cover that namespace.
The initial hosted aggregate preflight failed before compilation; its precise
failed command was not observable from the aggregate label. Fixing that verified
namespace collision is not proof that the hosted failure cause is established.

Packaging diagnostics now separate input layout, each archive architecture,
Xcode XCFramework creation, output layout, notice copying and package inspection.
Inspector failures emit only a fixed category (metadata, header, module map,
architecture, required/test symbols, notices, file access or tool/schema error).
Raw values, subprocess output and paths are not emitted. Inspector checks use
explicit conditions, not Python assertions that disappear under optimization.
The latest hosted run reached both Rust builds; its combined packaging failure
has not yet been localized, and this diagnostic patch does not claim a fix for
an unobserved Xcode or archive error.

Archive tool diagnostics identify `lipo` versus `nm` and device versus simulator.
`nm -g -j -U` still requires successful inspection of the whole static archive,
all declared C ABI symbols and no test-only exports. A nonzero command exit is
never rescued by partial stdout. Finite stderr categories distinguish recognized
bitcode-format, option and object-format errors; unknown failures remain generic.
These categories are diagnostics, not proof of root cause. No archive members
are skipped, no test is disabled, and no alternative tool is installed.
Rust static archives may include LLVM bitcode members; an incompatible reader
can fail even when architecture inspection/package assembly succeeds. That is a
hypothesis until a recognized diagnostic appears, not an established failure here.
Reference: https://llvm.org/docs/CommandGuide/llvm-nm.html

### Matching the Rust archive reader

Hosted diagnostics localized the previous failure to Apple's `nm` reading the
simulator archive's bitcode. The revised check uses `llvm-nm` from the official
Rust 1.100.0 `llvm-tools-preview` component for **both** archives. Only the existing
CI Rust toolchain installation is extended; there is no local installation,
Homebrew tool, Apple upgrade, archive rewriting or member exclusion.

Preflight and inspection resolve the reader inside the pinned rustc sysroot,
require an ARM64 macOS Rust 1.100.0 host, require the `llvm-nm` file to exist and
compare its LLVM numeric version to `rustc -vV`. Missing tools/version mismatch
fail closed. Component inventory is not assumed stable across Rust versions.

`--extern-only --defined-only --format=just-symbols` preserves the prior external,
defined-symbol check. Both slices must still contain every header ABI symbol and
no forbidden test exports; partial stdout after any tool error remains failure.
The package bytes, Rust build recipe, source and dependency lock are unchanged.
Apple link compatibility and consumer tests remain subsequent independent gates.

Official references:
https://rust-lang.github.io/rustup/concepts/components.html
https://llvm.org/docs/CommandGuide/llvm-nm.html
