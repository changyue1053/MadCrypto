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
