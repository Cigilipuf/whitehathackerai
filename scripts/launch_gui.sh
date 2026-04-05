#!/usr/bin/env bash
# WhiteHatHacker AI — GUI Launch Script
# Place this on your path or run directly: bash scripts/launch_gui.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Activate virtualenv if present
if [[ -f "$PROJECT_DIR/.venv/bin/activate" ]]; then
    source "$PROJECT_DIR/.venv/bin/activate"
elif [[ -f "$PROJECT_DIR/venv/bin/activate" ]]; then
    source "$PROJECT_DIR/venv/bin/activate"
fi

# Load .env if present
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Ensure output dirs
mkdir -p output/{scans,programs,global_logs,reports}

exec python3 scripts/launch_gui.py "$@"
