#!/usr/bin/env bash
set -euo pipefail
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done
if [ -n "$OUT" ] && [ -d "$OUT" ]; then
  for p in "$OUT"/*.pid; do
    [ -f "$p" ] || continue
    pid=$(cat "$p" || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
else
  pkill -f '[p]acketin_attack.py' 2>/dev/null || true
  pkill -f "ping -i" 2>/dev/null || true
  pkill -f "iperf -c" 2>/dev/null || true
  # Avoid broad "hping3" match, which can hit parent orchestrator command lines.
  pkill -f "hping3 --udp --flood" 2>/dev/null || true

  # Best-effort local cleanup for stray flood attackers without matching orchestrator args.
  pkill -f "hping3 --udp --flood" 2>/dev/null || true
  pkill -f '[p]acketin_attack.py' 2>/dev/null || true
fi

echo "cleanup_done"
