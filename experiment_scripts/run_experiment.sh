#!/usr/bin/env bash
set -euo pipefail
NAME="test1"
RATE=1200
SIZE=64
DURATION=90
MITIGATION=on
OUT_BASE="results"
CONTROLLER="http://127.0.0.1:8080"
ATTACK_METHOD="scapy"
ATTACK_IFACE="h2-eth0"
ATTACK_LENGTH=""
ATTACK_TARGET=""
ATTACK_TARGET_PREFIX="10.0.0."
VALID_TARGET="10.0.0.3"
CONTROLLER_IFACE=""
VALID_MODE="both"
VALID_NEW_DELAY=10
ATTACK_DELAY=5
CMD_PREFIX_ATTACK=""
CMD_PREFIX_VALID=""
IPERF=off
THRESHOLD=""

while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2;;
    --rate) RATE="$2"; shift 2;;
    --size) SIZE="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;
    --mitigation) MITIGATION="$2"; shift 2;;
    --out-base) OUT_BASE="$2"; shift 2;;
    --controller) CONTROLLER="$2"; shift 2;;
    --attack-target) ATTACK_TARGET="$2"; shift 2;;
    --attack-target-prefix) ATTACK_TARGET_PREFIX="$2"; shift 2;;
    --valid-target) VALID_TARGET="$2"; shift 2;;
    --controller-iface) CONTROLLER_IFACE="$2"; shift 2;;
    --valid-mode) VALID_MODE="$2"; shift 2;;
    --valid-new-delay) VALID_NEW_DELAY="$2"; shift 2;;
    --attack-delay) ATTACK_DELAY="$2"; shift 2;;
    --attack-cmd-prefix) CMD_PREFIX_ATTACK="$2"; shift 2;;
    --valid-cmd-prefix) CMD_PREFIX_VALID="$2"; shift 2;;
    --iperf) IPERF="$2"; shift 2;;
    --threshold) THRESHOLD="$2"; shift 2;;
    --attack-method) ATTACK_METHOD="$2"; shift 2;;
    --attack-iface) ATTACK_IFACE="$2"; shift 2;;
    --attack-length) ATTACK_LENGTH="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$OUT_BASE/${NAME}_$(date +%H%M%S)"
mkdir -p "$OUT"
cat > "$OUT/config.json" <<EOF
{"name":"$NAME","rate":$RATE,"size":$SIZE,"duration":$DURATION,"mitigation":"$MITIGATION","controller":"$CONTROLLER","attack_target":"$ATTACK_TARGET","attack_target_prefix":"$ATTACK_TARGET_PREFIX","valid_target":"$VALID_TARGET","controller_iface":"$CONTROLLER_IFACE","valid_mode":"$VALID_MODE","valid_new_delay":$VALID_NEW_DELAY,"attack_delay":$ATTACK_DELAY,"iperf":"$IPERF","threshold":"$THRESHOLD","attack_method":"$ATTACK_METHOD","attack_iface":"$ATTACK_IFACE","attack_length":"$ATTACK_LENGTH"}
EOF
{
  echo "experiment_start=$(date -Iseconds)"
  echo "output_dir=$OUT"
} > "$OUT/experiment.log"
# reset and configure controller if reachable
curl -s -X POST "$CONTROLLER/config/reset" >> "$OUT/experiment.log" 2>&1 || true

echo "[INFO] Clearing switch flow tables..." >> "$OUT/experiment.log"

for sw in s1 s2 s3 s4; do
  sudo ovs-ofctl -O OpenFlow13 del-flows "$sw" 2>/dev/null || true
done

if [ "$MITIGATION" = "on" ]; then
  curl -s -X POST -H 'Content-Type: application/json' -d '{"enabled": true}' "$CONTROLLER/config/mitigation" >> "$OUT/experiment.log" 2>&1 || true
else
  curl -s -X POST -H 'Content-Type: application/json' -d '{"enabled": false}' "$CONTROLLER/config/mitigation" >> "$OUT/experiment.log" 2>&1 || true
fi

if [ -n "$THRESHOLD" ]; then
  curl -s -X POST -H 'Content-Type: application/json' -d "{\"threshold\": $THRESHOLD}" "$CONTROLLER/config/threshold" >> "$OUT/experiment.log" 2>&1 || true
fi

# start collectors and valid traffic
python3 "$SCRIPT_DIR/collect_metrics.py" --duration "$DURATION" --out "$OUT" --controller "$CONTROLLER" --iface "$CONTROLLER_IFACE" ${THRESHOLD:+--threshold "$THRESHOLD"} > "$OUT/collector_stdout.log" 2> "$OUT/collector_stderr.log" &
echo $! > "$OUT/collector.pid"
"$SCRIPT_DIR/start_valid_flows.sh" --target "$VALID_TARGET" --duration "$DURATION" --size "$SIZE" --out "$OUT" --mode "$VALID_MODE" --new-delay "$VALID_NEW_DELAY" --cmd-prefix "$CMD_PREFIX_VALID" --iperf "$IPERF" >> "$OUT/experiment.log" 2>&1
sleep "$ATTACK_DELAY"

if [ -n "$ATTACK_LENGTH" ]; then
  ATTACK_DURATION="$ATTACK_LENGTH"
else
  ATTACK_DURATION=$((DURATION-ATTACK_DELAY))
fi

if [ "$ATTACK_DURATION" -lt 1 ]; then
  ATTACK_DURATION=1
fi


if [ -n "$ATTACK_TARGET" ]; then
  "$SCRIPT_DIR/start_attack.sh" \
  --rate "$RATE" \
  --size "$SIZE" \
  --duration "$ATTACK_DURATION" \
  --target "$ATTACK_TARGET" \
  --out "$OUT" \
  --cmd-prefix "$CMD_PREFIX_ATTACK" \
  --method "$ATTACK_METHOD" \
  --iface "$ATTACK_IFACE" >> "$OUT/experiment.log" 2>&1
else
  "$SCRIPT_DIR/start_attack.sh" \
  --rate "$RATE" \
  --size "$SIZE" \
  --duration "$ATTACK_DURATION" \
  --target-prefix "$ATTACK_TARGET_PREFIX" \
  --out "$OUT" \
  --cmd-prefix "$CMD_PREFIX_ATTACK" \
  --method "$ATTACK_METHOD" \
  --iface "$ATTACK_IFACE" >> "$OUT/experiment.log" 2>&1
fi

#(
#  while true; do
#    for sw in s1 s2 s3 s4; do
#      sudo ovs-ofctl -O OpenFlow13 del-flows "$sw" 2>/dev/null || true
#    done
#    sleep 1
#  done
#) &
#FLOW_CLEAR_PID=$!


sleep "$ATTACK_DURATION"
sudo pkill -f hping3 2>/dev/null || true
sudo pkill -f packetin_attack.py 2>/dev/null || true

##
#kill $FLOW_CLEAR_PID 2>/dev/null || true
##

wait "$(cat "$OUT/collector.pid")" || true

"$SCRIPT_DIR/cleanup.sh" --out "$OUT" >> "$OUT/experiment.log" 2>&1 || true
echo "experiment_end=$(date -Iseconds)" >> "$OUT/experiment.log"
echo "done: $OUT"
