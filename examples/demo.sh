#!/usr/bin/env bash
# Runs a scripted client against the hostile test server through the sentinel, then prints the report.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin && go build -o bin/ ./cmd/...
rm -f /tmp/sentinel-demo.jsonl /tmp/sentinel-demo-pins.json
echo "== scan =="; ./bin/mcp-sentinel scan -- ./bin/evil-mcp || true
echo; echo "== proxy =="
./bin/mcp-sentinel proxy -policy examples/policy.example.json -audit /tmp/sentinel-demo.jsonl -pins /tmp/sentinel-demo-pins.json -name evil -- ./bin/evil-mcp < examples/session.jsonl | cut -c1-170
echo; echo "== report =="; ./bin/mcp-sentinel report -html docs/report.html /tmp/sentinel-demo.jsonl
