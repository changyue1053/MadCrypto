#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
root=$PWD
exec 3>&1
mkdir -p build/ios-package-check/logs
exec >>build/ios-package-check/logs/simulator.log 2>&1
stage=sim-prerequisites
trap 'printf "FAIL: %s\n" "$stage" >&3' ERR
[[ $(uname -m) == arm64 ]]
export DEVELOPER_DIR=/Applications/Xcode_26.2.app/Contents/Developer
[[ $(xcodebuild -version) == $'Xcode 26.2\nBuild version 17C52' ]]
out="$root/build/ios-package-check"
[[ ! -e "$out/consumer" && ! -e "$out/tests.xcresult" ]]
cp -R ios-package-check/Consumer "$out/consumer"
mkdir "$out/consumer/Artifacts"
cp -R "$out/MadCrypto.xcframework" "$out/consumer/Artifacts/"
runtime=com.apple.CoreSimulator.SimRuntime.iOS-26-2
xcrun simctl list runtimes available -j | python3 -c 'import json,sys; assert any(x["identifier"]=="com.apple.CoreSimulator.SimRuntime.iOS-26-2" and x["isAvailable"] for x in json.load(sys.stdin)["runtimes"])'
stage=sim-create
uuid=$(xcrun simctl create "MadCrypto-package-check-$$" com.apple.CoreSimulator.SimDeviceType.iPhone-16 "$runtime")
[[ $uuid =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]
cleanup() { xcrun simctl shutdown "$uuid" >/dev/null 2>&1 || true; xcrun simctl delete "$uuid" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage=sim-boot
xcrun simctl boot "$uuid"
xcrun simctl bootstatus "$uuid" -b
[[ $(xcrun simctl spawn "$uuid" uname -m) == arm64 ]]
cd "$out/consumer"
stage=unsigned-device-consumer
xcodebuild -scheme MadCryptoPackageCheck -destination 'generic/platform=iOS' \
  -derivedDataPath "$out/device-consumer" ARCHS=arm64 ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO build
printf 'PASS: unsigned-device-consumer-build-only\n' >&3
stage=xctest-execute
xcodebuild -scheme MadCryptoPackageCheck -destination "platform=iOS Simulator,id=$uuid" \
  -destination-timeout 120 -derivedDataPath "$out/simulator-consumer" \
  -resultBundlePath "$out/tests.xcresult" -parallel-testing-enabled NO \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- \
  CODE_SIGNING_REQUIRED=NO test
stage=named-result-parse
python3 "$root/ios-package-check/results.py" >&3 2>&3
