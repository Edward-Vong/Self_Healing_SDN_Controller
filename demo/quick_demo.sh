#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXP_DIR="$ROOT_DIR/experiment_scripts"
SWITCHES_CONF="$EXP_DIR/switches.conf"

if [ -f "$SWITCHES_CONF" ]; then
  # shellcheck disable=SC1090
  . "$SWITCHES_CONF"
fi

USER_NAME="${USER:-}"
TRUSTED_HOST="${TRUSTED:-}"
ATTACKER_HOST="${ATTACKER:-}"
VICTIM_HOST="${VICTIM:-}"
CONTROLLER_URL="${CONTROLLER:-http://127.0.0.1:8080}"
PROJECT_DIR_VAL="${PROJECT_DIR:-$ROOT_DIR}"
ATTACK_IFACE_VAL="${ATTACK_IFACE:-eth1}"
ATTACK_TARGET="${VICTIM_DATA_IP:-10.10.3.2}"
VALID_TARGET="${VALID_TARGET_IP:-10.10.2.2}"
ATTACKER_PYTHON_BIN="${ATTACKER_PYTHON_BIN:-python3.8}"

DURATION="${DEMO_DURATION:-75}"
ATTACK_LENGTH="${DEMO_ATTACK_LENGTH:-60}"
RATE="${DEMO_RATE:-4000}"
SIZE="${DEMO_SIZE:-256}"
THRESHOLD="${DEMO_THRESHOLD:-300}"
ATTACK_METHOD="${DEMO_ATTACK_METHOD:-hping3}"
RATE_TOLERANCE="${DEMO_RATE_TOLERANCE:-0.95}"
HOLD_DURATION="${DEMO_HOLD_DURATION:-10}"
REACH_TIMEOUT="${DEMO_REACH_TIMEOUT:-30}"
TARGET_PPS="${DEMO_TARGET_PPS:-$THRESHOLD}"
WATCH_EXTRA="${DEMO_WATCH_EXTRA:-90}"

PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ]; then
  if command -v python3.8 >/dev/null 2>&1; then
    PYTHON_BIN="python3.8"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    echo "[ERROR] No Python found on controller" >&2
    exit 2
  fi
fi

for n in USER_NAME TRUSTED_HOST ATTACKER_HOST VICTIM_HOST; do
  if [ -z "${!n}" ]; then
    echo "[ERROR] Missing required config: $n (check $SWITCHES_CONF)" >&2
    exit 2
  fi
done

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_BASE="$ROOT_DIR/results/demo"
OUT_DIR="$OUT_BASE/quick_demo_$STAMP"
mkdir -p "$OUT_DIR"

WATCH_LOG="$OUT_DIR/watch_controller_state.log"
DRIVER_LOG="$OUT_DIR/quick_demo.driver.log"

cleanup() {
  local rc=$?
  if [ -n "${RUN_PID:-}" ] && kill -0 "$RUN_PID" >/dev/null 2>&1; then
    kill "$RUN_PID" >/dev/null 2>&1 || true
    wait "$RUN_PID" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

echo "[INFO] Demo output dir: $OUT_DIR"
echo "[INFO] Launching quick demo experiment in background"
echo "[INFO] duration=$DURATION attack_length=$ATTACK_LENGTH rate=$RATE size=$SIZE threshold=$THRESHOLD monitor_target=$TARGET_PPS method=$ATTACK_METHOD hold=${HOLD_DURATION}s timeout=${REACH_TIMEOUT}s tolerance=$RATE_TOLERANCE watch_extra=${WATCH_EXTRA}s"

RUN_EXPERIMENT_VERBOSE=0 bash "$EXP_DIR/run_experiment.sh" \
  --name "demo_quick" \
  --out-base "$OUT_BASE" \
  --duration "$DURATION" \
  --attack-delay 0 \
  --attack-length "$ATTACK_LENGTH" \
  --rate "$RATE" \
  --size "$SIZE" \
  --mitigation on \
  --threshold "$THRESHOLD" \
  --attack-method "$ATTACK_METHOD" \
  --attack-iface "$ATTACK_IFACE_VAL" \
  --attack-target "$ATTACK_TARGET" \
  --valid-target "$VALID_TARGET" \
  --controller "$CONTROLLER_URL" \
  --attack-cmd-prefix "ssh -n -T -o BatchMode=yes -o ConnectTimeout=8 $USER_NAME@$ATTACKER_HOST" \
  --valid-cmd-prefix "ssh -n -T -o BatchMode=yes -o ConnectTimeout=8 $USER_NAME@$TRUSTED_HOST" \
  --iperf-server-cmd-prefix "ssh -n -T -o BatchMode=yes -o ConnectTimeout=8 $USER_NAME@$VICTIM_HOST" \
  --iperf on \
  --attack-python-bin "$ATTACKER_PYTHON_BIN" \
  --user "$USER_NAME" \
  --trusted "$TRUSTED_HOST" \
  --attacker "$ATTACKER_HOST" \
  --victim "$VICTIM_HOST" \
  --project-dir "$PROJECT_DIR_VAL" \
  > "$DRIVER_LOG" 2>&1 &
RUN_PID=$!

sleep 1

echo "[INFO] Monitoring flat-rate controller stats"
"$PYTHON_BIN" "$SCRIPT_DIR/watch_controller_state.py" \
  --mode flat \
  --controller "$CONTROLLER_URL" \
  --duration "$((DURATION + WATCH_EXTRA))" \
  --interval 1 \
  --target-pps "$TARGET_PPS" \
  --rate-tolerance "$RATE_TOLERANCE" \
  --hold-duration "$HOLD_DURATION" \
  --reach-timeout "$REACH_TIMEOUT" \
  --log "$WATCH_LOG" | tee "$OUT_DIR/watch_console.log"

RUN_RC=0
wait "$RUN_PID" || RUN_RC=$?
unset RUN_PID

if [ "$RUN_RC" -ne 0 ]; then
  echo "[WARN] Experiment exited non-zero (code=$RUN_RC). See $DRIVER_LOG"
fi

sleep 1

echo "[DONE] Demo run complete"
echo "[DONE] Watch log: $WATCH_LOG"
echo "[DONE] Driver log: $DRIVER_LOG"
echo "[TIP] Replot demo runs with: bash $EXP_DIR/run_all_tests.sh --replot --trim-start 5"
