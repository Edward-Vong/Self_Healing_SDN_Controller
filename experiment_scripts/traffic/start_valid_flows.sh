#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="$(cd "$SCRIPT_DIR/.." && pwd)/config.sh"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

TARGET="$DEFAULT_MININET_VALID_TARGET"
DURATION="$DEFAULT_VALID_FLOW_DURATION"
INTERVAL="$DEFAULT_VALID_FLOW_INTERVAL"
SIZE="$DEFAULT_VALID_FLOW_PACKET_SIZE"
OUT="results/tmp"
MODE="both"
NEW_DELAY="$DEFAULT_VALID_FLOW_NEW_DELAY"
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

case "$MODE" in
  existing|new|both) ;;
  *) echo "Unknown valid flow mode: $MODE" >&2; exit 2 ;;
esac

if [ -z "$TARGET" ]; then
  echo "Missing valid traffic target" >&2
  exit 2
fi

run_command_bg() {
  local name="$1"
  local command="$2"
  local full_command="$command"

  if [ -n "$CMD_PREFIX" ]; then
    full_command="$CMD_PREFIX $command"
  fi

  eval "$full_command" > "$OUT/${name}.log" 2> "$OUT/${name}.err" &
  echo $! > "$OUT/${name}.pid"
}

run_delayed_bg() {
  local name="$1"
  local delay="$2"
  local command="$3"
  local full_command="$command"

  if [ -n "$CMD_PREFIX" ]; then
    full_command="$CMD_PREFIX $command"
  fi

  ( sleep "$delay"; eval "$full_command" ) > "$OUT/${name}.log" 2> "$OUT/${name}.err" &
  echo $! > "$OUT/${name}.pid"
}

run_bg() {
  local name="$1"; shift
  run_command_bg "$name" "$*"
}
if [ "$MODE" = "existing" ] || [ "$MODE" = "both" ]; then
  run_bg ping_existing "ping -i '$INTERVAL' -s '$SIZE' -w '$DURATION' '$TARGET'"
  if [ "$IPERF" = "on" ]; then
    run_bg iperf_existing "iperf -c '$TARGET' -t '$DURATION' -i 1"
  fi
fi
if [ "$MODE" = "new" ] || [ "$MODE" = "both" ]; then
  new_duration=$((DURATION-NEW_DELAY))
  if [ "$new_duration" -gt 0 ]; then
    run_delayed_bg ping_new "$NEW_DELAY" "ping -i '$INTERVAL' -s '$SIZE' -w '$new_duration' '$TARGET'"
    if [ "$IPERF" = "on" ]; then
      run_delayed_bg iperf_new "$NEW_DELAY" "iperf -c '$TARGET' -t '$new_duration' -i 1"
    fi
  fi
fi
echo "valid_flows_started mode=$MODE target=$TARGET"
