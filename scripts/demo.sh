#!/usr/bin/env bash
# Demo orchestration: backend (8001) + Next.js prod (3000) + ngrok HTTPS tunnel.
# One-time prereqs (NOT done here):
#   cd backend && uv sync
#   cd frontend && npm install && npm run build
#   ngrok config add-authtoken <token>
#   ~/.config/ngrok/ngrok.yml must define the `utc` tunnel (see docs/demo-setup.md)
#
# Run: ./scripts/demo.sh
# Stop: Ctrl-C (all three children are killed together)

set -euo pipefail
cd "$(dirname "$0")/.."

trap 'kill 0' EXIT INT TERM

( cd backend && uv run uvicorn url_threat_checker.main:app --host 127.0.0.1 --port 8001 ) &
( cd frontend && npm run start ) &
ngrok start utc

wait
