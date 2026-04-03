#!/usr/bin/env bash
set -euo pipefail

echo "=== Check SOC Platform Env ==="

echo "[PATH] $PATH"
echo

for bin in python3 git jq gh node npm snyk; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "[OK] $bin -> $(command -v "$bin")"
  else
    echo "[FAIL] $bin no encontrado"
  fi
done

echo
echo "=== Python imports ==="
python3 - <<'PY'
mods = ["psycopg"]
for mod in mods:
    try:
        __import__(mod)
        print(f"[OK] import {mod}")
    except Exception as e:
        print(f"[FAIL] import {mod}: {e}")
PY

echo
echo "=== GitHub auth ==="
if command -v gh >/dev/null 2>&1; then
  gh auth status || true
fi

echo
echo "=== Snyk auth ==="
if command -v snyk >/dev/null 2>&1; then
  snyk whoami || true
fi