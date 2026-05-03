#!/usr/bin/env bash
set -euo pipefail
TARGET="10.0.0.3"
DURATION=30
INTERVAL=0.5
SIZE=56
OUT="results/tmp"
MODE="both"
NEW_DELAY=10
CMD_PREFIX=""
IPERF=off
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;
    --interval) INTERVAL="$2"; shift 2;;
    --size) SIZE="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --new-delay) NEW_DELAY="$2"; shift 2;;
    --cmd-prefix) CMD_PREFIX="$2"; shift 2;;
    --iperf) IPERF="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done
mkdir -p "$OUT"
run_bg() {
  local name="$1"; shift
  if [ -n "$CMD_PREFIX" ]; then
    eval "$CMD_PREFIX $*" > "$OUT/${name}.log" 2> "$OUT/${name}.err" &
  else
    eval "$*" > "$OUT/${name}.log" 2> "$OUT/${name}.err" &
  fi
  echo $! > "$OUT/${name}.pid"
}
if [ "$MODE" = "existing" ] || [ "$MODE" = "both" ]; then
  run_bg ping_existing "ping -i '$INTERVAL' -s '$SIZE' -w '$DURATION' '$TARGET'"
  if [ "$IPERF" = "on" ]; then
    run_bg iperf_existing "iperf -c '$TARGET' -t '$DURATION' -i 1"
  fi
fi
if [ "$MODE" = "new" ] || [ "$MODE" = "both" ]; then
  ( sleep "$NEW_DELAY"; if [ -n "$CMD_PREFIX" ]; then eval "$CMD_PREFIX ping -i '$INTERVAL' -s '$SIZE' -w '$((DURATION-NEW_DELAY))' '$TARGET'"; else eval "ping -i '$INTERVAL' -s '$SIZE' -w '$((DURATION-NEW_DELAY))' '$TARGET'"; fi ) > "$OUT/ping_new.log" 2> "$OUT/ping_new.err" &
  echo $! > "$OUT/ping_new.pid"
  if [ "$IPERF" = "on" ]; then
    ( sleep "$NEW_DELAY"; if [ -n "$CMD_PREFIX" ]; then eval "$CMD_PREFIX iperf -c '$TARGET' -t '$((DURATION-NEW_DELAY))' -i 1"; else eval "iperf -c '$TARGET' -t '$((DURATION-NEW_DELAY))' -i 1"; fi ) > "$OUT/iperf_new.log" 2> "$OUT/iperf_new.err" &
    echo $! > "$OUT/iperf_new.pid"
  fi
fi
echo "valid_flows_started mode=$MODE target=$TARGET"
