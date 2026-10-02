#!/usr/bin/env bash
# Rulează cu: sudo bash assets/capture-demo.sh
set -e
BIN="/home/7sh1d0w7x/opencode/dev/projects/state-witness/target/debug/state-witness"
OUT="/home/7sh1d0w7x/opencode/dev/projects/state-witness/assets"
"$BIN" ssh        > "$OUT/demo-output.txt"  2>&1 || true
"$BIN" ssh --json > "$OUT/demo-output.json" 2>&1 || true
echo "✅ capturat: demo-output.txt + .json"
cat "$OUT/demo-output.txt"
