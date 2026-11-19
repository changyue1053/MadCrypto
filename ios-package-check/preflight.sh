#!/usr/bin/env bash
# Every tool's raw output stays local; only fixed source-controlled labels escape.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/ios-package-check/logs
run_stage() {
  local stage=$1
  shift
  if "$@" >"build/ios-package-check/logs/$stage.log" 2>&1; then
    printf 'PASS: %s\n' "$stage"
  else
    printf 'FAIL: %s\n' "$stage" >&2
    exit 1
  fi
}
run_stage preflight-arm64 bash -euo pipefail -c 'test "$(uname -m)" = arm64'
run_stage preflight-xcode bash -euo pipefail -c 'test "$(xcodebuild -version)" = "$(printf "Xcode 26.2\nBuild version 17C52")"'
run_stage preflight-rust-install rustup toolchain install 1.100.0 --profile minimal --no-self-update
run_stage preflight-rust-llvm-tools rustup component add --toolchain 1.100.0 llvm-tools-preview
run_stage preflight-rust-llvm-reader python3 ios-package-check/package_inspector.py --check-llvm-tools
run_stage preflight-rust-targets rustup target add --toolchain 1.100.0 aarch64-apple-ios aarch64-apple-ios-sim
run_stage preflight-cargo-fetch cargo fetch --locked --target aarch64-apple-ios --target aarch64-apple-ios-sim
run_stage preflight-synthetic-formats python3 ios-package-check/test_formats.py
