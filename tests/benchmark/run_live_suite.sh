#!/bin/bash
# run_live_suite.sh - Bash entrypoint for live benchmark suite.
set -euo pipefail

PYTHONUNBUFFERED=1 python3 -u "$(dirname "$0")/run_live_suite.py" "$@"

