#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
METRICS_DIR="$SCRIPT_DIR/metrics"
TRAFFIC_DIR="$SCRIPT_DIR/traffic"
CONFIG_FILE="$SCRIPT_DIR/config.sh"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

NAME="test1"
RATE="$DEFAULT_ATTACK_RATE"
SIZE="$DEFAULT_PACKET_SIZE"
DURATION="$DEFAULT_EXPERIMENT_DURATION"
MITIGATION=on
OUT_BASE="results"
CONTROLLER="${CONTROLLER:-$DEFAULT_CONTROLLER_URL}"
ATTACK_METHOD="$DEFAULT_ATTACK_METHOD"
ATTACK_IFACE="${ATTACK_IFACE:-$DEFAULT_MININET_ATTACK_IFACE}"
ATTACK_LENGTH=""
ATTACK_TARGET=""
ATTACK_TARGET_PREFIX="$DEFAULT_ATTACK_TARGET_PREFIX"
VALID_TARGET=""
CONTROLLER_IFACE=""
VALID_MODE="both"
VALID_NEW_DELAY="$DEFAULT_RUN_EXPERIMENT_VALID_NEW_DELAY"
ATTACK_DELAY="$DEFAULT_RUN_EXPERIMENT_ATTACK_DELAY"
CMD_PREFIX_ATTACK=""
CMD_PREFIX_VALID=""
ATTACK_PYTHON_BIN="$DEFAULT_ATTACKER_PYTHON_BIN"
IPERF=off
IPERF_SERVER_PREFIX=""
THRESHOLD=""
REMOTE_SCRIPT_DIR=""
CLEAR_OVS=auto
SWITCH_IPS=""

if [ -z "${OVS_SWITCHES:-}" ]; then
  OVS_SWITCHES="s1 s2 s3 s4"
fi
# Use SWITCH_MONITOR_IPS from config.sh as the default for --switch-ips.
SWITCH_IPS="${SWITCH_IPS:-${SWITCH_MONITOR_IPS:-}}"

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
    --attack-python-bin) ATTACK_PYTHON_BIN="$2"; shift 2;;
    --iperf) IPERF="$2"; shift 2;;
    --iperf-server-cmd-prefix) IPERF_SERVER_PREFIX="$2"; shift 2;;
    --threshold) THRESHOLD="$2"; shift 2;;
    --attack-method) ATTACK_METHOD="$2"; shift 2;;
    --attack-iface) ATTACK_IFACE="$2"; shift 2;;
    --attack-length) ATTACK_LENGTH="$2"; shift 2;;
    --remote-script-dir) REMOTE_SCRIPT_DIR="$2"; shift 2;;
    --user) USER="$2"; shift 2;;
    --trusted) TRUSTED="$2"; shift 2;;
    --attacker) ATTACKER="$2"; shift 2;;
    --victim) VICTIM="$2"; shift 2;;
    --project-dir) PROJECT_DIR="$2"; shift 2;;
    --clear-ovs) CLEAR_OVS="$2"; shift 2;;
    --switch-ips) SWITCH_IPS="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "$PYTHON_BIN" ]; then
  if ! PYTHON_BIN="$(select_python_bin)"; then
    echo "[ERROR] No supported Python interpreter found" >&2
    exit 2
  fi
fi

# Derive practical defaults so routine CloudLab runs need fewer flags.
if [ -z "$ATTACK_TARGET" ]; then
  if [ -n "$VICTIM_DATA_IP" ]; then
    ATTACK_TARGET="$VICTIM_DATA_IP"
  elif [ -n "$VICTIM" ]; then
    ATTACK_TARGET="$VICTIM"
  fi
fi

if [ -z "$VALID_TARGET" ] && [ -n "$VALID_TARGET_IP" ]; then
  VALID_TARGET="$VALID_TARGET_IP"
fi

if [ -n "$USER" ] && [ -n "$ATTACKER" ] && [ -z "$CMD_PREFIX_ATTACK" ]; then
  CMD_PREFIX_ATTACK="ssh $USER@$ATTACKER"
fi

if [ -n "$USER" ] && [ -n "$TRUSTED" ] && [ -z "$CMD_PREFIX_VALID" ]; then
  CMD_PREFIX_VALID="ssh $USER@$TRUSTED"
fi

if [ -n "$USER" ] && [ -n "$VICTIM" ] && [ -z "$IPERF_SERVER_PREFIX" ]; then
  IPERF_SERVER_PREFIX="ssh $USER@$VICTIM"
fi

if [ -z "$REMOTE_SCRIPT_DIR" ]; then
  if [ -n "$PROJECT_DIR" ]; then
    REMOTE_SCRIPT_DIR="$PROJECT_DIR/experiment_scripts/traffic"
  else
    REMOTE_SCRIPT_DIR="$TRAFFIC_DIR"
  fi
fi

OUT="$OUT_BASE/${NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

cat > "$OUT/config.json" <<EOF_JSON
{"name":"$NAME","rate":$RATE,"size":$SIZE,"duration":$DURATION,"mitigation":"$MITIGATION","controller":"$CONTROLLER","attack_target":"$ATTACK_TARGET","attack_target_prefix":"$ATTACK_TARGET_PREFIX","valid_target":"$VALID_TARGET","controller_iface":"$CONTROLLER_IFACE","valid_mode":"$VALID_MODE","valid_new_delay":$VALID_NEW_DELAY,"attack_delay":$ATTACK_DELAY,"iperf":"$IPERF","threshold":"$THRESHOLD","attack_method":"$ATTACK_METHOD","attack_iface":"$ATTACK_IFACE","attack_length":"$ATTACK_LENGTH","remote_script_dir":"$REMOTE_SCRIPT_DIR","user":"$USER","trusted":"$TRUSTED","attacker":"$ATTACKER","victim":"$VICTIM","project_dir":"$PROJECT_DIR"}
EOF_JSON

{
  echo "experiment_start=$(date -Iseconds)"
  echo "output_dir=$OUT"
  echo "attack_method=$ATTACK_METHOD"
  echo "mitigation=$MITIGATION"
} > "$OUT/experiment.log"

RUN_VERBOSE="${RUN_EXPERIMENT_VERBOSE:-0}"

run_log() {
  local msg="$1"
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] $msg" >> "$OUT/experiment.log"
  if [ "$RUN_VERBOSE" = "1" ]; then
    echo "[$ts] [run_experiment:$NAME] $msg"
  fi
}

sleep_with_progress() {
  local total="$1"
  local label="$2"
  local step=15
  local elapsed=0
  local remaining=0

  if [ -z "$total" ] || [ "$total" -le 0 ] 2>/dev/null; then
    return
  fi

  while [ "$elapsed" -lt "$total" ]; do
    remaining=$((total - elapsed))
    if [ "$remaining" -lt "$step" ]; then
      sleep "$remaining"
      elapsed=$total
    else
      sleep "$step"
      elapsed=$((elapsed + step))
    fi
    run_log "[INFO] ${label} progress ${elapsed}/${total}s"
  done
}

on_term() {
  run_log "[ERROR] Received SIGTERM/SIGINT; ATTACK_DELAY=$ATTACK_DELAY ATTACK_DURATION=${ATTACK_DURATION:-unset}"
  ps -o pid,ppid,pgid,sid,comm,args -p $$ >> "$OUT/experiment.log" 2>/dev/null || true
  exit 143
}

trap on_term TERM INT
run_log "[INFO] Starting run with PID=$$ duration=$DURATION attack_delay=$ATTACK_DELAY"

append_event() {
  local event="$1"
  local value="${2:-}"
  local now t
  now=$(date +%s.%N)
  t=$(awk "BEGIN {printf \"%.3f\", $now - $START_EPOCH}")
  echo "$event,$t,$now,$value" >> "$DRIVER_EVENTS"
}

# reset and configure controller if reachable
curl -s -X POST "$CONTROLLER/config/reset" >> "$OUT/experiment.log" 2>&1 || true
curl -s -X POST "$CONTROLLER/trust/clear" >> "$OUT/experiment.log" 2>&1 || true
curl -s -X POST "$CONTROLLER/mitigate/end" >> "$OUT/experiment.log" 2>&1 || true
run_log "[INFO] Controller reset/config endpoints attempted"

if { [ "$CLEAR_OVS" = "on" ] || [ "$CLEAR_OVS" = "auto" ]; } && [ -n "$OVS_SWITCHES" ]; then
  echo "[INFO] Clearing local OVS flow tables if Mininet switches exist..." >> "$OUT/experiment.log"
  for sw in $OVS_SWITCHES; do
    sudo ovs-ofctl -O OpenFlow13 del-flows "$sw" >> "$OUT/experiment.log" 2>&1 || true
  done
fi

if [ "$MITIGATION" = "on" ]; then
  curl -s -X POST -H 'Content-Type: application/json' -d '{"enabled": true}' "$CONTROLLER/config/mitigation" >> "$OUT/experiment.log" 2>&1 || true
else
  curl -s -X POST -H 'Content-Type: application/json' -d '{"enabled": false}' "$CONTROLLER/config/mitigation" >> "$OUT/experiment.log" 2>&1 || true
fi

if [ -n "$THRESHOLD" ]; then
  curl -s -X POST -H 'Content-Type: application/json' -d "{\"threshold\": $THRESHOLD}" "$CONTROLLER/config/threshold" >> "$OUT/experiment.log" 2>&1 || true
fi

START_EPOCH=$(date +%s.%N)
DRIVER_EVENTS="$OUT/driver_events.csv"
echo "event,t,timestamp,value" > "$DRIVER_EVENTS"
run_log "[INFO] Metrics collection phase starting"

# Start iperf server on victim when requested. For Mininet/local testing, start it manually if needed.
if [ "$IPERF" = "on" ] && [ -n "$IPERF_SERVER_PREFIX" ]; then
  eval "$IPERF_SERVER_PREFIX iperf -s" > "$OUT/iperf_server.log" 2> "$OUT/iperf_server.err" &
  echo $! > "$OUT/iperf_server.pid"
  run_log "[INFO] Started remote iperf server helper pid=$(cat "$OUT/iperf_server.pid" 2>/dev/null || echo unknown)"
  sleep 1
fi

# Default switch IPs to valid+attack targets if not explicitly set.
COLLECTOR_ARGS=(
  --duration "$DURATION"
  --out "$OUT"
  --controller "$CONTROLLER"
  --iface "$CONTROLLER_IFACE"
)
if [ -n "$THRESHOLD" ]; then
  COLLECTOR_ARGS+=(--threshold "$THRESHOLD")
fi

if [ -z "$SWITCH_IPS" ]; then
  _ips=""
  [ -n "$VALID_TARGET" ] && _ips="$VALID_TARGET"
  if [ -n "$ATTACK_TARGET" ] && [ "$ATTACK_TARGET" != "$VALID_TARGET" ]; then
    _ips="${_ips:+$_ips,}$ATTACK_TARGET"
  fi
  [ -n "$_ips" ] && COLLECTOR_ARGS+=(--switch-ips "$_ips")
else
  COLLECTOR_ARGS+=(--switch-ips "$SWITCH_IPS")
fi

# Start collectors first, then legitimate warm-up traffic.
"$PYTHON_BIN" "$METRICS_DIR/collect_metrics.py" "${COLLECTOR_ARGS[@]}" > "$OUT/collector_stdout.log" 2> "$OUT/collector_stderr.log" &
echo $! > "$OUT/collector.pid"
run_log "[INFO] Started collector pid=$(cat "$OUT/collector.pid" 2>/dev/null || echo unknown)"
for _ in 1 2 3 4 5; do
  [ -f "$OUT/events.csv" ] && break
  sleep 0.2
done

bash "$TRAFFIC_DIR/start_valid_flows.sh" --target "$VALID_TARGET" --duration "$DURATION" --size "$SIZE" --out "$OUT" --mode "$VALID_MODE" --new-delay "$VALID_NEW_DELAY" --cmd-prefix "$CMD_PREFIX_VALID" --iperf "$IPERF" >> "$OUT/experiment.log" 2>&1 \
  || echo "[WARN] start_valid_flows exited non-zero; legitimate traffic may be absent" >> "$OUT/experiment.log"
append_event "valid_traffic_started" "$VALID_MODE" || true
run_log "[INFO] Valid traffic launched (mode=$VALID_MODE)"

sleep_with_progress "$ATTACK_DELAY" "attack_delay"
run_log "[INFO] Attack delay phase completed"

if [ -n "$ATTACK_LENGTH" ]; then
  ATTACK_DURATION="$ATTACK_LENGTH"
else
  ATTACK_DURATION=$((DURATION-ATTACK_DELAY))
fi

if [ "${RATE:-0}" -gt 0 ] && [ "${ATTACK_DURATION:-0}" -gt 0 ]; then
  RUN_ATTACK=yes
else
  RUN_ATTACK=no
fi

if [ "$RUN_ATTACK" = "yes" ]; then
  append_event "attack_started" "$ATTACK_METHOD" || true

  # When the attack runs over SSH, ATTACK_PYTHON_BIN refers to the attacker node's Python.
  # When running locally (Mininet), use the locally-detected interpreter.
  _attack_python="${CMD_PREFIX_ATTACK:+$ATTACK_PYTHON_BIN}"
  _attack_python="${_attack_python:-$PYTHON_BIN}"

  ATTACK_LAUNCH_RC=0
  bash "$TRAFFIC_DIR/start_attack.sh" \
    --rate "$RATE" \
    --size "$SIZE" \
    --duration "$ATTACK_DURATION" \
    --target "$ATTACK_TARGET" \
    --target-prefix "$ATTACK_TARGET_PREFIX" \
    --out "$OUT" \
    --cmd-prefix "$CMD_PREFIX_ATTACK" \
    --method "$ATTACK_METHOD" \
    --iface "$ATTACK_IFACE" \
    --remote-script-dir "$REMOTE_SCRIPT_DIR" \
    --python-bin "$_attack_python" >> "$OUT/experiment.log" 2>&1 || ATTACK_LAUNCH_RC=$?

  if [ "$ATTACK_LAUNCH_RC" -ne 0 ]; then
    run_log "[ERROR] start_attack.sh exited with code $ATTACK_LAUNCH_RC; aborting run"
    exit "$ATTACK_LAUNCH_RC"
  fi

  sleep 2
  if [ -f "$OUT/attack.pid" ]; then
    attack_pid="$(cat "$OUT/attack.pid" 2>/dev/null || true)"
    if [ -n "$attack_pid" ] && ! kill -0 "$attack_pid" 2>/dev/null; then
      run_log "[ERROR] attack process died immediately; aborting run"
      {
        echo "----- attack_stdout.log -----"
        cat "$OUT/attack_stdout.log" 2>/dev/null || true
        echo "----- attack_stderr.log -----"
        cat "$OUT/attack_stderr.log" 2>/dev/null || true
      } >> "$OUT/experiment.log"
      exit 1
    fi
  fi

  sleep_with_progress "$ATTACK_DURATION" "attack_window"
  append_event "attack_ended" "$ATTACK_METHOD" || true
else
  echo "[INFO] No attack launched because rate=$RATE or attack duration=$ATTACK_DURATION" >> "$OUT/experiment.log"
  run_log "[INFO] No attack launched; sleeping attack window ATTACK_DURATION=$ATTACK_DURATION"
  sleep_with_progress "$ATTACK_DURATION" "attack_window"
fi

# Stop attack processes on the attacker host when running remotely.
if [ -n "$CMD_PREFIX_ATTACK" ]; then
  eval "$CMD_PREFIX_ATTACK 'sudo pkill -f [p]acketin_attack.py'" 2>/dev/null || true
else
  sudo pkill -f '[p]acketin_attack.py' 2>/dev/null || true
fi

wait "$(cat "$OUT/collector.pid")" || true
run_log "[INFO] Collector wait completed"

if [ -f "$DRIVER_EVENTS" ]; then
  if [ ! -f "$OUT/events.csv" ]; then
    echo "event,t,timestamp,value" > "$OUT/events.csv"
  fi
  tail -n +2 "$DRIVER_EVENTS" >> "$OUT/events.csv"
fi

bash "$TRAFFIC_DIR/cleanup.sh" --out "$OUT" >> "$OUT/experiment.log" 2>&1 || true

if [ "$IPERF" = "on" ] && [ -n "$IPERF_SERVER_PREFIX" ]; then
  eval "$IPERF_SERVER_PREFIX 'pkill -f iperf'" >> "$OUT/experiment.log" 2>&1 || true
fi

echo "experiment_end=$(date -Iseconds)" >> "$OUT/experiment.log"
run_log "[INFO] Run completed successfully"

# Move output files into subdirectories so the run directory is easy to navigate manually.
# config.json stays at the root as a quick-reference identity file.
mkdir -p "$OUT/csv" "$OUT/plots" "$OUT/logs"
for _f in "$OUT"/*.csv;  do [ -f "$_f" ] && mv "$_f" "$OUT/csv/"  || true; done
for _f in "$OUT"/*.json; do
  [ -f "$_f" ] || continue
  [ "$(basename "$_f")" = "config.json" ] && continue
  mv "$_f" "$OUT/csv/"
done
for _f in "$OUT"/*.log "$OUT"/*.err "$OUT"/*.pid; do [ -f "$_f" ] && mv "$_f" "$OUT/logs/" || true; done
unset _f

echo "done: $OUT"
