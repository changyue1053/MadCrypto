#!/usr/bin/env bash
# grep status 1 means clean; matching input AND inspection errors fail closed.
set -euo pipefail
if grep -E '^(openssl|aws-lc|ring |cmake |libsqlite3|rusqlite|madcrypto-store)' "$1" >/dev/null 2>&1; then
  exit 1
else
  status=$?
  if [[ $status -ne 1 ]]; then
    exit 1
  fi
fi
