#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out="$root/build/android-package-check"
[[ ! -e "$out" && ! -L "$out" ]]
mkdir -p "$out/logs"
exec 3>&1
exec >"$out/logs/check.log" 2>&1
stage=android-preflight
trap 'printf "FAIL: %s\n" "$stage" >&3' ERR
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]]
export RUSTUP_TOOLCHAIN=1.100.0
sdk=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
[[ -n "$sdk" && -s "$sdk/licenses/android-sdk-license" ]]
manager="$sdk/cmdline-tools/latest/bin/sdkmanager"
[[ -x "$manager" ]]
# No --licenses, yes pipe, new acceptance or interactive fallback.
stage=android-existing-license-provision
"$manager" --sdk_root="$sdk" 'ndk;28.2.13676358' </dev/null
ndk="$sdk/ndk/28.2.13676358"
grep -Eq '^Pkg.Revision *= *28\.2\.13676358\r?$' "$ndk/source.properties"
bin="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
cc="$bin/aarch64-linux-android23-clang"
[[ -x "$cc" && -x "$bin/llvm-readelf" && -x "$bin/llvm-ar" ]]
printf 'PASS: android-ndk-preflight\n' >&3
stage=android-rust-provision
rustup toolchain install 1.100.0 --profile minimal --no-self-update
rustup target add --toolchain 1.100.0 aarch64-linux-android
[[ $(rustc --version) == 'rustc 1.100.0 '* ]]
cargo fetch --locked --target aarch64-linux-android
stage=android-dependency-generate
python3 android-package-check/dependency_check.py generate "$out/dependencies.txt" >&3
stage=android-dependency-scope
bash android-package-check/dependency_scope.sh "$out/dependencies.txt" >&3
stage=android-archive
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET
export CARGO_TARGET_DIR="$out/target"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$cc"
export CC_aarch64_linux_android="$cc" AR_aarch64_linux_android="$bin/llvm-ar"
cargo rustc --locked --offline -p madcrypto-ffi --lib --crate-type staticlib --release --no-default-features --target aarch64-linux-android
mkdir -p "$out/stage/include" "$out/stage/lib" "$out/stage/notices"
cp crates/madcrypto-ffi/include/madcrypto.h "$out/stage/include/"
cp "$CARGO_TARGET_DIR/aarch64-linux-android/release/libmadcrypto_ffi.a" "$out/stage/lib/"
cp LICENSE THIRD_PARTY.md "$out/stage/notices/"
"$bin/llvm-ar" t "$out/stage/lib/libmadcrypto_ffi.a" >"$out/archive-members.txt"
[[ -s "$out/archive-members.txt" ]]
printf 'PASS: android-static-archive\n' >&3
stage=android-relocated-consumer
mv "$out/stage" "$out/relocated-sdk"
[[ ! -e "$out/stage" ]]
mkdir "$out/consumer"
cp android-package-check/consumer.c "$out/consumer/consumer.c"
cd "$out/consumer"
"$cc" -std=c11 -Wall -Wextra -Werror -fPIE -pie -I../relocated-sdk/include consumer.c \
  ../relocated-sdk/lib/libmadcrypto_ffi.a -ldl -lm -Wl,--no-undefined -Wl,-z,defs \
  -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 -o consumer
"$bin/llvm-readelf" -h -l -d -s consumer >"$out/consumer-elf.txt"
# These must be definitions, not unresolved references or discarded test code.
"$bin/llvm-nm" --defined-only consumer >"$out/consumer-symbols.txt"
grep -Eq ' [Tt] madcrypto_abi_version$' "$out/consumer-symbols.txt"
grep -Eq ' [Tt] madcrypto_selftest$' "$out/consumer-symbols.txt"
printf 'PASS: android-independent-consumer-link\n' >&3
stage=android-final-elf
python3 "$root/android-package-check/elf_check.py" consumer >&3
stage=android-manifest
export MADCRYPTO_CHECK_SOURCE_SHA=$(git -C "$root" rev-parse HEAD)
python3 - "$out" <<'PY'
import hashlib,json,sys,os
from pathlib import Path
out=Path(sys.argv[1]); package=out/'relocated-sdk'
files={str(p.relative_to(package)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(package.rglob('*')) if p.is_file()}
(out/'manifest.json').write_text(json.dumps({'source_commit':os.environ['MADCRYPTO_CHECK_SOURCE_SHA'],'target':'aarch64-linux-android','api':23,'ndk':'28.2.13676358','rust':'1.100.0','files':files,'consumer_sha256':hashlib.sha256((out/'consumer/consumer').read_bytes()).hexdigest(),'android_execution':False,'redistribution':False},indent=2)+'\n')
PY
printf 'PASS: android-package-check-no-runtime-claim\n' >&3
