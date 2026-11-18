#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tests/test_package_host.py
# No source-tree include or library paths are passed to either app build.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 scripts/package_host.py "$work/original-sdk"
mv "$work/original-sdk" "$work/relocated sdk"
sdk="$work/relocated sdk"
python3 - "$sdk" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]); m=json.loads((p/'manifest.json').read_text())
assert m['target']=='x86_64-unknown-linux-gnu' and m['features']==[]
assert {str(f.relative_to(p)) for f in p.rglob('*') if f.is_file()} == set(m['files']) | {'manifest.json'}
for name,digest in m['files'].items():
    assert hashlib.sha256((p/name).read_bytes()).hexdigest()==digest,name
PY
for app in app_a app_b; do
  cp -R "tests/standalone/$app" "$work/$app"
  cmake -S "$work/$app" -B "$work/build-$app" -DCMAKE_PREFIX_PATH="$sdk" -DCMAKE_BUILD_TYPE=Release
  cmake --build "$work/build-$app"
  ctest --test-dir "$work/build-$app" --output-on-failure
 done
# Parallel, separate processes must not depend on another SDK or host registry.
"$work/build-app_a/app_a" & a=$!
"$work/build-app_b/app_b" & b=$!
wait "$a"; wait "$b"
# Two different package roots must not silently share one imported target.
mkdir "$work/conflict"
cat > "$work/conflict/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.16)
project(PackageConflict C)
add_library(MadCrypto::MadCrypto STATIC IMPORTED)
set_target_properties(MadCrypto::MadCrypto PROPERTIES IMPORTED_LOCATION "/different/sdk/lib.a")
find_package(MadCrypto CONFIG REQUIRED)
CMAKE
if cmake -S "$work/conflict" -B "$work/build-conflict" -DCMAKE_PREFIX_PATH="$sdk" > "$work/conflict.log" 2>&1; then
  echo 'ERROR: different existing target silently accepted'; exit 1
fi
grep -q 'A different MadCrypto target is already loaded' "$work/conflict.log"
# Wrong-platform package consumption must fail at configuration, never silently link.
if cmake -S "$work/app_a" -B "$work/wrong-platform" -DCMAKE_PREFIX_PATH="$sdk" -DCMAKE_SYSTEM_NAME=Generic > "$work/wrong-platform.log" 2>&1; then
  echo 'ERROR: Linux artifact accepted for another platform'; exit 1
fi
grep -q 'Linux x86_64 host artifacts only' "$work/wrong-platform.log"
if [[ -n "${MADOBS_INCLUDE_DIR:-}" ]]; then
  cc -std=c11 -Wall -Wextra -Werror -I"$sdk/include" -I"$MADOBS_INCLUDE_DIR" \
    tests/obs_adapter.c "$sdk/lib/libmadcrypto_ffi.a" -lpthread -ldl -lm -o "$work/obs-app"
  "$work/obs-app"
else
  echo 'SKIPPED optional package MadObs adapter; set MADOBS_INCLUDE_DIR'
fi
# Fail closed rather than replacing an existing SDK directory.
if python3 scripts/package_host.py "$sdk" > "$work/overwrite.log" 2>&1; then
  echo 'ERROR: existing SDK replaced'; exit 1
fi
grep -q 'refusing overwrite' "$work/overwrite.log"
echo 'PASS: relocated package, C/C++ independent apps, parallel processes, platform rejection, overwrite refusal'
