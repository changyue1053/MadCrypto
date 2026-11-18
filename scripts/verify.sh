#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p madcrypto-ffi --locked
# C consumer links the real static library, not an alternate C implementation.
cc -std=c11 -Wall -Wextra -Werror -Icrates/madcrypto-ffi/include \
  samples/c/main.c target/debug/libmadcrypto_ffi.a -lpthread -ldl -lm -o target/c-consumer
target/c-consumer
if [[ -n "${MADOBS_INCLUDE_DIR:-}" ]]; then
  cc -std=c11 -Wall -Wextra -Werror -Icrates/madcrypto-ffi/include \
    -Iadapters/obs -I"$MADOBS_INCLUDE_DIR" tests/obs_adapter.c \
    target/debug/libmadcrypto_ffi.a -lpthread -ldl -lm -o target/obs-consumer
  target/obs-consumer
else
  echo 'SKIPPED: optional MadObs header adapter test; set MADOBS_INCLUDE_DIR'
fi
cargo metadata --locked --format-version 1 > target/dependency-inventory.json
python3 scripts/public_audit.py
