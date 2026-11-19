#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
exec 3>&1
mkdir -p build/ios-package-check/logs
exec >>build/ios-package-check/logs/build.log 2>&1
stage=apple-preflight
trap 'printf "FAIL: %s\n" "$stage" >&3' ERR
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]]
export DEVELOPER_DIR=/Applications/Xcode_26.2.app/Contents/Developer
export RUSTUP_TOOLCHAIN=1.100.0
[[ $(xcodebuild -version) == $'Xcode 26.2\nBuild version 17C52' ]]
[[ $(rustc --version) == 'rustc 1.100.0 '* ]]
export IPHONEOS_DEPLOYMENT_TARGET=16.0
export CARGO_TARGET_DIR="$PWD/build/ios-package-check/rust"
out="$PWD/build/ios-package-check"
[[ ! -e "$out/MadCrypto.xcframework" && ! -e "$CARGO_TARGET_DIR" ]]
mkdir -p "$out/headers" "$out/notices"
cp crates/madcrypto-ffi/include/madcrypto.h "$out/headers/"
printf 'module MadCrypto { header "madcrypto.h" export * }\n' >"$out/headers/module.modulemap"
cp LICENSE THIRD_PARTY.md "$out/notices/"
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  stage=rust-device
  sdk=iphoneos
  if [[ $target == aarch64-apple-ios-sim ]]; then stage=rust-simulator; sdk=iphonesimulator; fi
  [[ $(xcrun --sdk "$sdk" --show-sdk-version) == 26.2 ]]
  cargo rustc -p madcrypto-ffi --lib --crate-type staticlib --locked --offline --release \
    --target "$target" --no-default-features
  printf 'PASS: %s\n' "$stage" >&3
done
stage=xcode-package
xcodebuild -create-xcframework \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libmadcrypto_ffi.a" -headers "$out/headers" \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libmadcrypto_ffi.a" -headers "$out/headers" \
  -output "$out/MadCrypto.xcframework"
# Development verification only, no binary publication or license-compliance claim.
cp -R "$out/notices" "$out/MadCrypto.xcframework/Notices"
python3 ios-package-check/inspect.py
printf 'PASS: xcode-package-inspection\n' >&3
