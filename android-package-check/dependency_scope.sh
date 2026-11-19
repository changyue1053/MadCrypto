#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(dirname "$0")/dependency_check.py" scope "$1"
