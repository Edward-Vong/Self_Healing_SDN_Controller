#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$EXP_DIR/.." && pwd)"
CONFIG_FILE="$EXP_DIR/config.sh"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

USER_NAME="${USER:-}"
TRUSTED_HOST="${TRUSTED:-}"
ATTACKER_HOST="${ATTACKER:-}"
VICTIM_HOST="${VICTIM:-}"
CONTROLLER_URL="${CONTROLLER:-$DEFAULT_CONTROLLER_URL}"
PROJECT_DIR_VAL="${PROJECT_DIR:-$ROOT_DIR}"
ATTACK_IFACE_VAL="${ATTACK_IFACE:-$DEFAULT_CLOUDLAB_ATTACK_IFACE}"
ATTACK_TARGET="${VICTIM_DATA_IP:-$DEFAULT_VICTIM_DATA_IP}"
VALID_TARGET="${VALID_TARGET_IP:-$DEFAULT_VALID_TARGET_IP}"
ATTACKER_PYTHON_BIN="${ATTACKER_PYTHON_BIN:-$DEFAULT_ATTACKER_PYTHON_BIN}"

DURATION="${DEMO_DURATION:-$DEFAULT_DEMO_DURATION}"
ATTACK_LENGTH="${DEMO_ATTACK_LENGTH:-$DEFAULT_DEMO_ATTACK_LENGTH}"
RATE="${DEMO_RATE:-$DEFAULT_DEMO_RATE}"
SIZE="${DEMO_SIZE:-$DEFAULT_SATURATION_PACKET_SIZE}"
THRESHOLD="${DEMO_THRESHOLD:-$DEFAULT_DEMO_THRESHOLD}"
ATTACK_METHOD="${DEMO_ATTACK_METHOD:-$DEFAULT_ATTACK_METHOD}"
RATE_TOLERANCE="${DEMO_RATE_TOLERANCE:-$DEFAULT_DEMO_RATE_TOLERANCE}"
HOLD_DURATION="${DEMO_HOLD_DURATION:-$DEFAULT_DEMO_HOLD_DURATION}"
REACH_TIMEOUT="${DEMO_REACH_TIMEOUT:-$DEFAULT_DEMO_REACH_TIMEOUT}"
TARGET_PPS="${DEMO_TARGET_PPS:-$THRESHOLD}"
WATCH_EXTRA="${DEMO_WATCH_EXTRA:-0}"

PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ]; then
  if ! PYTHON_BIN="$(select_python_bin)"; then
    echo "[ERROR] No Python found on controller" >&2
    exit 2
  fi
fi

for n in USER_NAME TRUSTED_HOST ATTACKER_HOST VICTIM_HOST; do
  if [ -z "${!n}" ]; then
    echo "[ERROR] Missing required config: $n (check $CONFIG_FILE)" >&2
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
