#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SWITCHES_CONF="$SCRIPT_DIR/switches.conf"
CURRENT_STAGE="startup"

RESULTS_DIR="$ROOT_DIR/results"
mkdir -p "$RESULTS_DIR"

RUN_STARTED_AT="$(date -Iseconds)"
STATUS_FILE="$RESULTS_DIR/last_run_status.json"
STATUS_TEXT_FILE="$RESULTS_DIR/last_run_status.txt"

if [ -f "$SWITCHES_CONF" ]; then
  # shellcheck disable=SC1090
  . "$SWITCHES_CONF"
fi

# Management-plane SSH endpoints.
USER_NAME="${USER:-}"
TRUSTED_HOST="${TRUSTED:-}"
ATTACKER_HOST="${ATTACKER:-}"
VICTIM_HOST="${VICTIM:-}"

# Data-plane IPs used as traffic targets.
# VICTIM_DATA_IP   = victim's IP reachable from the attacker (attack target, 10.10.3.x).
# VALID_TARGET_IP  = victim's IP reachable from the trusted node (ping/iperf target, 10.10.2.x).
# These differ because the CloudLab topology uses point-to-point /24 subnets per pair.
TRUSTED_DATA_IP="${TRUSTED_DATA_IP:-10.10.2.1}"
ATTACKER_DATA_IP="${ATTACKER_DATA_IP:-10.10.3.1}"
VICTIM_DATA_IP="${VICTIM_DATA_IP:-10.10.3.2}"
VALID_TARGET_IP="${VALID_TARGET_IP:-10.10.2.2}"

CONTROLLER_URL="${CONTROLLER:-http://127.0.0.1:8080}"
CONTROLLER_IFACE_VAL="${CONTROLLER_IFACE:-eth0}"
PROJECT_DIR_VAL="${PROJECT_DIR:-$ROOT_DIR}"
SWITCH_MONITOR_IPS_VAL="${SWITCH_MONITOR_IPS:-}"
OVS_SWITCHES="${OVS_SWITCHES:-}"

# Experiment defaults (fast profile).
RUN_BASELINE_CONTROL=on
RUN_SATURATION=on
RUN_CORE=on
RUN_SWEEPS=on
RUN_RATE_SWEEP=on
RUN_SIZE_SWEEP=on
CLEAR_OVS_MODE="off"

DURATION=75
ATTACK_DELAY=0
ATTACK_LENGTH=60
ATTACK_IFACE="${ATTACK_IFACE:-eth1}"
SCAPY_RATE=1200
SIZE_SWEEP_RATE=1200
SIZE_SWEEP_SIZES="64,256,512"
SATURATION_ATTACK_METHOD="scapy"
SATURATION_STEP_DURATION=15
SATURATION_RATES="1000,5000,10000,20000,50000"
SATURATION_MITIGATION_MODE="off"
SATURATION_SIZE=256
THRESHOLD_OVERRIDE=""
THRESHOLD_SET_BY_USER=0
FAILED_RUNS=""
TRIM_START=5        # seconds of topology-learning warmup to exclude from plots
REPLOT_ONLY=0       # set to 1 via --replot to regenerate plots without re-running experiments
DRY_RUN=0           # set to 1 via --dry-run to validate config/connectivity only
PYTHON_BIN="${PYTHON_BIN:-}"
ATTACKER_PYTHON_BIN="${ATTACKER_PYTHON_BIN:-python3.8}"

if [ -z "$PYTHON_BIN" ]; then
  if command -v python3.8 >/dev/null 2>&1; then
    PYTHON_BIN="python3.8"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    echo "[ERROR] No Python interpreter found (python3.8/python3)" >&2
    exit 2
  fi
fi

log_stage() {
  CURRENT_STAGE="$*"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

write_status() {
  local status="$1"
  local code="$2"
  local message="$3"
  local safe_stage="$CURRENT_STAGE"
  local safe_message="$message"
  safe_stage="${safe_stage//\\/\\\\}"
  safe_stage="${safe_stage//\"/\\\"}"
  safe_stage="${safe_stage//$'\n'/ }"
  safe_message="${safe_message//\\/\\\\}"
  safe_message="${safe_message//\"/\\\"}"
  safe_message="${safe_message//$'\n'/ }"
  cat > "$STATUS_FILE" <<EOF_JSON
{"status":"$status","exit_code":$code,"stage":"$safe_stage","message":"$safe_message","started_at":"$RUN_STARTED_AT","finished_at":"$(date -Iseconds)"}
EOF_JSON
  printf '%s\n' "status=$status" "exit_code=$code" "stage=$CURRENT_STAGE" "message=$message" > "$STATUS_TEXT_FILE"
}

on_err() {
  local code=$?
  local line_no="${BASH_LINENO[0]:-unknown}"
  local cmd="${BASH_COMMAND:-unknown}"
  log_stage "[ERROR] run_all_tests failed at line $line_no with exit code $code"
  log_stage "[ERROR] Failing command: $cmd"
  write_status "failed" "$code" "line=$line_no command=$cmd"
  exit "$code"
}

trap on_err ERR
write_status "running" "0" "run_all_tests started"

usage() {
  cat <<EOF
Usage: $0 [options]

Runs the full CloudLab experiment suite and generates all result plots.

Options:
  --controller URL             Controller REST URL (default: $CONTROLLER_URL)
  --user USER                  SSH username (default from switches.conf)
  --trusted-host HOST          Trusted node SSH host/IP
  --attacker-host HOST         Attacker node SSH host/IP
  --victim-host HOST           Victim node SSH host/IP
  --trusted-data-ip IP         Trusted dataplane IP (default: $TRUSTED_DATA_IP)
  --attacker-data-ip IP        Attacker dataplane IP (default: $ATTACKER_DATA_IP)
  --victim-data-ip IP          Victim attack-target IP  (attacker→victim subnet, default: $VICTIM_DATA_IP)
  --valid-target-ip IP         Victim valid-traffic IP  (trusted→victim subnet, default: $VALID_TARGET_IP)
  --project-dir DIR            Repo path on remote nodes (default from switches.conf or local)
  --controller-iface IFACE     Controller interface for utilization metrics
  --attack-iface IFACE         Attacker egress iface for scapy (default: $ATTACK_IFACE)
  --attacker-python-bin BIN    Python executable on attacker (default: $ATTACKER_PYTHON_BIN)
  --duration SEC               Duration for main runs (default: $DURATION)
  --attack-delay SEC           Delay before attack starts (default: $ATTACK_DELAY)
  --attack-length SEC          Attack duration inside each run (default: $ATTACK_LENGTH)
  --scapy-rate PPS             Scapy PPS (default: $SCAPY_RATE)
  --size-sweep-rate PPS        Scapy PPS for packet-size sweep (default: $SIZE_SWEEP_RATE)
  --size-sweep-sizes CSV       Packet sizes for Scapy size sweep, bytes (default: $SIZE_SWEEP_SIZES)
  --saturation-attack-method M Saturation method: scapy|udp (default: $SATURATION_ATTACK_METHOD)
  --saturation-step-duration S Saturation step duration seconds (default: $SATURATION_STEP_DURATION)
  --saturation-rates CSV       Saturation rates CSV, pps (default: $SATURATION_RATES)
  --saturation-mitigation-mode M  Saturation mitigation mode: keep|on|off (default: $SATURATION_MITIGATION_MODE)
  --saturation-size BYTES      Saturation packet size bytes (default: $SATURATION_SIZE)
  --threshold N                Skip baseline threshold extraction and use N
  --run-baseline-control       Run baseline collect_metrics stage (uses derived threshold unless --threshold is also provided)
  --skip-baseline-control      Skip baseline collect_metrics stage
  --skip-saturation            Skip saturation finder stage
  --skip-core                  Skip core 3 comparison runs
  --switch-monitor-ips CSV     IPs/hosts to ping for switch RTT metrics (default: config or valid+attack targets)
  --skip-sweeps                Skip rate and size sweeps
  --skip-rate-sweep            Skip only the Scapy rate sweep
  --skip-size-sweep            Skip only the Scapy packet-size sweep
  --clear-ovs MODE             on|off|auto for run_experiment.sh (default: $CLEAR_OVS_MODE)
  --trim-start SEC             Seconds of warm-up data to exclude from plots (default: $TRIM_START)
  --replot                     Regenerate plots from existing results without re-running experiments
  --dry-run                    Validate config and SSH connectivity only; do not run any experiments
  -h, --help                   Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER_URL="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --trusted-host) TRUSTED_HOST="$2"; shift 2 ;;
    --attacker-host) ATTACKER_HOST="$2"; shift 2 ;;
    --victim-host) VICTIM_HOST="$2"; shift 2 ;;
    --trusted-data-ip) TRUSTED_DATA_IP="$2"; shift 2 ;;
    --attacker-data-ip) ATTACKER_DATA_IP="$2"; shift 2 ;;
    --victim-data-ip) VICTIM_DATA_IP="$2"; shift 2 ;;
    --valid-target-ip) VALID_TARGET_IP="$2"; shift 2 ;;
    --project-dir) PROJECT_DIR_VAL="$2"; shift 2 ;;
    --controller-iface) CONTROLLER_IFACE_VAL="$2"; shift 2 ;;
    --attack-iface) ATTACK_IFACE="$2"; shift 2 ;;
    --attacker-python-bin) ATTACKER_PYTHON_BIN="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --attack-delay) ATTACK_DELAY="$2"; shift 2 ;;
    --attack-length) ATTACK_LENGTH="$2"; shift 2 ;;
    --scapy-rate) SCAPY_RATE="$2"; shift 2 ;;
    --size-sweep-rate) SIZE_SWEEP_RATE="$2"; shift 2 ;;
    --size-sweep-sizes) SIZE_SWEEP_SIZES="$2"; shift 2 ;;
    --saturation-attack-method) SATURATION_ATTACK_METHOD="$2"; shift 2 ;;
    --saturation-step-duration) SATURATION_STEP_DURATION="$2"; shift 2 ;;
    --saturation-rates) SATURATION_RATES="$2"; shift 2 ;;
    --saturation-mitigation-mode) SATURATION_MITIGATION_MODE="$2"; shift 2 ;;
    --saturation-size) SATURATION_SIZE="$2"; shift 2 ;;
    --switch-monitor-ips) SWITCH_MONITOR_IPS_VAL="$2"; shift 2 ;;
    --threshold) THRESHOLD_OVERRIDE="$2"; THRESHOLD_SET_BY_USER=1; shift 2 ;;
    --run-baseline-control) RUN_BASELINE_CONTROL=on; shift ;;
    --skip-baseline-control) RUN_BASELINE_CONTROL=off; shift ;;
    --skip-saturation) RUN_SATURATION=off; shift ;;
    --skip-core) RUN_CORE=off; shift ;;
    --skip-sweeps) RUN_SWEEPS=off; RUN_RATE_SWEEP=off; RUN_SIZE_SWEEP=off; shift ;;
    --skip-rate-sweep) RUN_RATE_SWEEP=off; shift ;;
    --skip-size-sweep) RUN_SIZE_SWEEP=off; shift ;;
    --clear-ovs) CLEAR_OVS_MODE="$2"; shift 2 ;;
    --trim-start) TRIM_START="$2"; shift 2 ;;
    --replot) REPLOT_ONLY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -z "$SWITCH_MONITOR_IPS_VAL" ]; then
  SWITCH_MONITOR_IPS_VAL="$VALID_TARGET_IP,$VICTIM_DATA_IP"
fi

# Baseline-control derives threshold from measured traffic. If user set --threshold
# explicitly, that value takes precedence; otherwise clear any override so baseline runs.
if [ "$RUN_BASELINE_CONTROL" = "on" ] && [ "$THRESHOLD_SET_BY_USER" -eq 0 ]; then
  THRESHOLD_OVERRIDE=""
fi

require_non_empty() {
  local name="$1"
  local value="$2"
  if [ -z "$value" ]; then
    echo "[ERROR] Missing required value: $name" >&2
    exit 2
  fi
}

is_probable_dataplane_ip() {
  # Flag anything in a 10.x.x.x /8 — management IPs are 128.110.x.x on this topology.
  case "$1" in
    10.*) return 0 ;;
    *) return 1 ;;
  esac
}

require_non_empty "USER (SSH username)" "$USER_NAME"
require_non_empty "TRUSTED host" "$TRUSTED_HOST"
require_non_empty "ATTACKER host" "$ATTACKER_HOST"
require_non_empty "VICTIM host" "$VICTIM_HOST"
require_non_empty "VICTIM data IP" "$VICTIM_DATA_IP"
require_non_empty "VALID traffic target IP" "$VALID_TARGET_IP"

if is_probable_dataplane_ip "$TRUSTED_HOST" || is_probable_dataplane_ip "$ATTACKER_HOST" || is_probable_dataplane_ip "$VICTIM_HOST"; then
  echo "[ERROR] SSH hosts look like dataplane IPs (10.10.10.x). Use management eth0 hostnames/IPs for TRUSTED/ATTACKER/VICTIM." >&2
  exit 2
fi

STRICT_HOST_KEY_MODE="accept-new"
if ! ssh -o StrictHostKeyChecking=accept-new -G localhost >/dev/null 2>&1; then
  STRICT_HOST_KEY_MODE="no"
  echo "[WARN] SSH client does not support StrictHostKeyChecking=accept-new; falling back to StrictHostKeyChecking=no"
fi

SSH_OPTS="-n -T -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=$STRICT_HOST_KEY_MODE"
SCP_OPTS="-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=$STRICT_HOST_KEY_MODE"

SSH_TRUSTED="ssh $SSH_OPTS $USER_NAME@$TRUSTED_HOST"
SSH_ATTACKER="ssh $SSH_OPTS $USER_NAME@$ATTACKER_HOST"
SSH_VICTIM="ssh $SSH_OPTS $USER_NAME@$VICTIM_HOST"

CMD_PREFIX_ATTACK="ssh $SSH_OPTS $USER_NAME@$ATTACKER_HOST"
CMD_PREFIX_VALID="ssh $SSH_OPTS $USER_NAME@$TRUSTED_HOST"
CMD_PREFIX_IPERF="ssh $SSH_OPTS $USER_NAME@$VICTIM_HOST"

reset_controller_state() {
  local mitigation_mode="${1:-keep}"
  local payload

  log_stage "[INFO] Resetting controller state (mode=$mitigation_mode)"
  curl -fsS -X POST "$CONTROLLER_URL/config/reset" >/dev/null || true
  curl -fsS -X POST "$CONTROLLER_URL/trust/clear" >/dev/null || true
  curl -fsS -X POST "$CONTROLLER_URL/mitigate/end" >/dev/null || true

  case "$mitigation_mode" in
    on)
      payload='{"enabled": true}'
      curl -fsS -X POST -H 'Content-Type: application/json' -d "$payload" "$CONTROLLER_URL/config/mitigation" >/dev/null || true
      ;;
    off)
      payload='{"enabled": false}'
      curl -fsS -X POST -H 'Content-Type: application/json' -d "$payload" "$CONTROLLER_URL/config/mitigation" >/dev/null || true
      ;;
    keep)
      ;;
    *)
      log_stage "[WARN] Unknown mitigation mode '$mitigation_mode' for reset_controller_state"
      ;;
  esac
}

clear_remote_ovs_flows() {
  if [ "$CLEAR_OVS_MODE" = "off" ]; then
    return
  fi

  local br
  local target
  local host_cmd

  log_stage "[INFO] Clearing OVS flow tables on remote nodes (mode=$CLEAR_OVS_MODE, bridges=$OVS_SWITCHES)"
  for target in trusted attacker victim; do
    case "$target" in
      trusted) host_cmd="$SSH_TRUSTED" ;;
      attacker) host_cmd="$SSH_ATTACKER" ;;
      victim) host_cmd="$SSH_VICTIM" ;;
      *) continue ;;
    esac

    for br in $OVS_SWITCHES; do
      $host_cmd "sudo ovs-vsctl br-exists '$br' && sudo ovs-ofctl -O OpenFlow13 del-flows '$br' || true" >/dev/null 2>&1 || true
    done
  done
}

# --replot: regenerate all plots and summary from existing results, then exit.
# No SSH, no experiments — just re-runs plot_results.py and summarize_runs.py.
if [ "$REPLOT_ONLY" -eq 1 ]; then
  log_stage "[INFO] --replot mode: regenerating plots from existing results in $RESULTS_DIR"
  found=0
  for d in "$RESULTS_DIR"/*; do
    [ -d "$d" ] || continue
    [ -f "$d/config.json" ] || continue
    found=$((found+1))
    "$PYTHON_BIN" "$SCRIPT_DIR/plot_results.py" "$d" --trim-start "$TRIM_START" \
      || log_stage "[WARN] plot_results.py failed for $d"
  done
  "$PYTHON_BIN" "$SCRIPT_DIR/summarize_runs.py" "$RESULTS_DIR" --output "$RESULTS_DIR/summary" \
    || log_stage "[WARN] summarize_runs.py failed"
  "$PYTHON_BIN" "$SCRIPT_DIR/plot_rate_sweep_rtt.py" "$RESULTS_DIR" \
    || log_stage "[WARN] plot_rate_sweep_rtt.py failed"
  log_stage "[DONE] Replotted $found run(s) with trim-start=${TRIM_START}s"
  write_status "success" "0" "replot completed ($found runs)"
  exit 0
fi

# --dry-run: validate everything (config, SSH, controller API, scapy) then exit.
# No experiments are launched.
if [ "$DRY_RUN" -eq 1 ]; then
  log_stage "[DRY-RUN] === Preflight check ===  (no experiments will run)"
  log_stage "[DRY-RUN] Config:"
  echo "  USER=$USER_NAME"
  echo "  CONTROLLER=$CONTROLLER_URL  IFACE=$CONTROLLER_IFACE_VAL"
  echo "  TRUSTED=$TRUSTED_HOST   TRUSTED_DATA_IP=$TRUSTED_DATA_IP"
  echo "  ATTACKER=$ATTACKER_HOST  ATTACKER_DATA_IP=$ATTACKER_DATA_IP"
  echo "  VICTIM=$VICTIM_HOST     VICTIM_DATA_IP=$VICTIM_DATA_IP  VALID_TARGET_IP=$VALID_TARGET_IP"
  echo "  ATTACKER_PYTHON_BIN=$ATTACKER_PYTHON_BIN"
  echo "  ATTACK_IFACE=$ATTACK_IFACE  SIZE=256  ATTACK_LENGTH=${ATTACK_LENGTH}s  DURATION=${DURATION}s"
  echo "  SWITCH_MONITOR_IPS=$SWITCH_MONITOR_IPS_VAL"
  echo "  SCAPY_RATE=$SCAPY_RATE  SIZE_SWEEP_RATE=$SIZE_SWEEP_RATE  SIZE_SWEEP_SIZES=$SIZE_SWEEP_SIZES"
  echo "  THRESHOLD=${THRESHOLD_OVERRIDE:-<derived from baseline>}"
  echo "  RUN_BASELINE_CONTROL=$RUN_BASELINE_CONTROL  RUN_SATURATION=$RUN_SATURATION  RUN_CORE=$RUN_CORE"
  echo "  RUN_SWEEPS=$RUN_SWEEPS  RUN_RATE_SWEEP=$RUN_RATE_SWEEP  RUN_SIZE_SWEEP=$RUN_SIZE_SWEEP"

  failed=0

  log_stage "[DRY-RUN] Checking SSH connectivity..."
  for _node in trusted:$TRUSTED_HOST attacker:$ATTACKER_HOST victim:$VICTIM_HOST; do
    _role=${_node%%:*}; _host=${_node##*:}
    if ssh $SSH_OPTS "$USER_NAME@$_host" 'hostname' >/dev/null 2>&1; then
      echo "  [OK]  $_role ($USER_NAME@$_host)"
    else
      echo "  [FAIL] $_role ($USER_NAME@$_host) — SSH failed" >&2
      failed=$((failed+1))
    fi
  done

  log_stage "[DRY-RUN] Checking controller REST API..."
  if curl -fsS "$CONTROLLER_URL/stats" >/dev/null 2>&1; then
    echo "  [OK]  $CONTROLLER_URL/stats"
  else
    echo "  [FAIL] Cannot reach $CONTROLLER_URL/stats" >&2
    failed=$((failed+1))
  fi

  log_stage "[DRY-RUN] Checking Python on attacker ($ATTACKER_HOST)..."
  py_ver=$(ssh $SSH_OPTS "$USER_NAME@$ATTACKER_HOST" "$ATTACKER_PYTHON_BIN --version 2>&1") && \
    echo "  [OK]  $ATTACKER_PYTHON_BIN: $py_ver" || { echo "  [FAIL] $ATTACKER_PYTHON_BIN not found on attacker" >&2; failed=$((failed+1)); }

  log_stage "[DRY-RUN] Checking scapy on attacker ($ATTACKER_HOST) with sudo $ATTACKER_PYTHON_BIN..."
  scapy_ver=$(ssh $SSH_OPTS "$USER_NAME@$ATTACKER_HOST" "sudo -n $ATTACKER_PYTHON_BIN -c 'import scapy; print(scapy.__version__)'" 2>&1) && \
    echo "  [OK]  scapy $scapy_ver" || { echo "  [FAIL] scapy not available for sudo $ATTACKER_PYTHON_BIN on attacker (run: sudo $ATTACKER_PYTHON_BIN -m pip install scapy)" >&2; failed=$((failed+1)); }

  log_stage "[DRY-RUN] Checking attacker interface ($ATTACK_IFACE) exists and is usable..."
  if ssh $SSH_OPTS "$USER_NAME@$ATTACKER_HOST" "ip link show '$ATTACK_IFACE' >/dev/null 2>&1"; then
    iface_state=$(ssh $SSH_OPTS "$USER_NAME@$ATTACKER_HOST" "cat /sys/class/net/$ATTACK_IFACE/operstate 2>/dev/null || echo unknown")
    echo "  [OK]  interface $ATTACK_IFACE exists (operstate=$iface_state)"
    if [ "$iface_state" = "down" ] || [ "$iface_state" = "dormant" ] || [ "$iface_state" = "notpresent" ]; then
      echo "  [FAIL] attacker interface $ATTACK_IFACE is not link-up (operstate=$iface_state)" >&2
      failed=$((failed+1))
    fi
  else
    echo "  [FAIL] attacker interface $ATTACK_IFACE does not exist" >&2
    echo "         Hint: pass --attack-iface eth1 (or set ATTACK_IFACE in switches.conf)" >&2
    failed=$((failed+1))
  fi

  log_stage "[DRY-RUN] Checking Python on controller..."
  "$PYTHON_BIN" --version >/dev/null 2>&1 && \
    echo "  [OK]  $PYTHON_BIN" || { echo "  [FAIL] $PYTHON_BIN not found on controller" >&2; failed=$((failed+1)); }

  log_stage "[DRY-RUN] Verifying packetin_attack.py is present (SCP check)..."
  scp $SCP_OPTS "$SCRIPT_DIR/packetin_attack.py" "$USER_NAME@$ATTACKER_HOST:/tmp/_packetin_preflight_test.py" >/dev/null 2>&1 && \
    echo "  [OK]  SCP to attacker works" || { echo "  [FAIL] SCP to $ATTACKER_HOST failed" >&2; failed=$((failed+1)); }

  log_stage "[DRY-RUN] Checking reachability: trusted -> victim (VALID_TARGET_IP=$VALID_TARGET_IP)..."
  if ssh $SSH_OPTS "$USER_NAME@$TRUSTED_HOST" "ping -c 3 -W 2 '$VALID_TARGET_IP' >/tmp/ping_preflight_valid.log 2>&1 && grep -q ', 0% packet loss' /tmp/ping_preflight_valid.log"; then
    rtt=$(ssh $SSH_OPTS "$USER_NAME@$TRUSTED_HOST" "tail -1 /tmp/ping_preflight_valid.log" 2>/dev/null || true)
    echo "  [OK]  ping $VALID_TARGET_IP: $rtt"
  else
    echo "  [FAIL] trusted cannot reach victim at $VALID_TARGET_IP" >&2
    ssh $SSH_OPTS "$USER_NAME@$TRUSTED_HOST" "tail -5 /tmp/ping_preflight_valid.log" 2>/dev/null || true
    failed=$((failed+1))
  fi

  log_stage "[DRY-RUN] Checking reachability: attacker -> victim (VICTIM_DATA_IP=$VICTIM_DATA_IP)..."
  if ssh $SSH_OPTS "$USER_NAME@$ATTACKER_HOST" "ping -c 3 -W 2 '$VICTIM_DATA_IP' >/tmp/ping_preflight_attack.log 2>&1 && grep -q ', 0% packet loss' /tmp/ping_preflight_attack.log"; then
    rtt=$(ssh $SSH_OPTS "$USER_NAME@$ATTACKER_HOST" "tail -1 /tmp/ping_preflight_attack.log" 2>/dev/null || true)
    echo "  [OK]  ping $VICTIM_DATA_IP: $rtt"
  else
    echo "  [FAIL] attacker cannot reach victim at $VICTIM_DATA_IP" >&2
    ssh $SSH_OPTS "$USER_NAME@$ATTACKER_HOST" "tail -5 /tmp/ping_preflight_attack.log" 2>/dev/null || true
    failed=$((failed+1))
  fi

  echo ""
  if [ "$failed" -eq 0 ]; then
    log_stage "[DRY-RUN] All checks PASSED. Ready to run experiments."
    write_status "success" "0" "dry-run preflight all checks passed"
    exit 0
  else
    log_stage "[DRY-RUN] $failed check(s) FAILED. Fix the issues above before running experiments."
    write_status "failed" "1" "dry-run preflight $failed check(s) failed"
    exit 1
  fi
fi

$SSH_TRUSTED "hostname"
$SSH_ATTACKER "hostname"
$SSH_VICTIM "hostname"

log_stage "[INFO] Verifying controller API at $CONTROLLER_URL"
curl -fsS "$CONTROLLER_URL/stats" >/dev/null

CONNECTED_SWITCHES="$(curl -fsS "$CONTROLLER_URL/stats" | "$PYTHON_BIN" -c '
import json, sys
d = json.load(sys.stdin)
print(int(d.get("connected_switches", 0)))
')"

EXPECTED_SWITCHES=3

if [ "$CONNECTED_SWITCHES" -lt "$EXPECTED_SWITCHES" ]; then
  echo "[ERROR] Expected at least $EXPECTED_SWITCHES OpenFlow switches, but controller sees $CONNECTED_SWITCHES." >&2
  echo "[ERROR] Check ovs-lan1/ovs-lan2/ovs-lan3 controller connections." >&2
  exit 1
fi

log_stage "[INFO] OpenFlow switches connected: $CONNECTED_SWITCHES"

log_stage "[INFO] Ensuring packetin_attack.py exists on attacker"
$SSH_ATTACKER "mkdir -p '$PROJECT_DIR_VAL/experiment_scripts'"
scp $SCP_OPTS "$SCRIPT_DIR/packetin_attack.py" "$USER_NAME@$ATTACKER_HOST:$PROJECT_DIR_VAL/experiment_scripts/packetin_attack.py" >/dev/null

THRESHOLD="${THRESHOLD_OVERRIDE}"

if [ "$RUN_BASELINE_CONTROL" = "on" ] && [ -z "$THRESHOLD" ]; then
  reset_controller_state off
  log_stage "[INFO] Running baseline control collection (about 90s)"
  $SSH_VICTIM "nohup iperf -s >/tmp/iperf_server_control.log 2>&1 < /dev/null &" || true
  $SSH_TRUSTED "nohup ping -i 0.5 -w 90 '$VALID_TARGET_IP' >/tmp/ping_control.log 2>&1 < /dev/null &"
  $SSH_TRUSTED "nohup iperf -c '$VALID_TARGET_IP' -t 90 >/tmp/iperf_control.log 2>&1 < /dev/null &"

  "$PYTHON_BIN" "$SCRIPT_DIR/collect_metrics.py" \
    --duration 90 \
    --out "$RESULTS_DIR/control_normal_traffic" \
    --controller "$CONTROLLER_URL" \
    --iface "$CONTROLLER_IFACE_VAL" \
    --baseline

  THRESHOLD="$("$PYTHON_BIN" -c "import json; d=json.load(open('$RESULTS_DIR/control_normal_traffic/baseline_summary.json')); print(int((d['packet_in_rate']['max'] or 0) * 3))" 2>/dev/null)" || {
    THRESHOLD=300
    log_stage "[WARN] Could not read baseline_summary.json; using fallback threshold=$THRESHOLD"
  }
  log_stage "[INFO] Derived threshold=$THRESHOLD"
  # Enforce a minimum to avoid false-positive mitigation on all runs.
  if [ "${THRESHOLD:-0}" -lt 100 ] 2>/dev/null; then
    log_stage "[WARN] Derived threshold ($THRESHOLD) is dangerously low; raising to minimum 100"
    THRESHOLD=100
  fi
elif [ -z "$THRESHOLD" ]; then
  THRESHOLD=300
  log_stage "[WARN] Baseline skipped and no threshold override provided; using fallback threshold=$THRESHOLD"
else
  log_stage "[INFO] Using provided threshold=$THRESHOLD"
fi

if [ "$RUN_SATURATION" = "on" ]; then
  reset_controller_state "$SATURATION_MITIGATION_MODE"
  log_stage "[INFO] Running saturation finder"
  "$PYTHON_BIN" "$SCRIPT_DIR/saturation_finder.py" \
    --controller "$CONTROLLER_URL" \
    --out "$RESULTS_DIR/saturation_analysis" \
    --target "$VICTIM_DATA_IP" \
    --iface "$ATTACK_IFACE" \
    --attack-method "$SATURATION_ATTACK_METHOD" \
    --size "$SATURATION_SIZE" \
    --cmd-prefix "$SSH_ATTACKER" \
    --rtt-cmd-prefix "$SSH_TRUSTED" \
    --step-duration "$SATURATION_STEP_DURATION" \
    --rtt-threshold-ms 50 \
    --loss-threshold-percent 5 \
    --rates "$SATURATION_RATES" \
    --mitigation-mode "$SATURATION_MITIGATION_MODE" \
    --controller-iface "$CONTROLLER_IFACE_VAL" \
    --switch-ips "$SWITCH_MONITOR_IPS_VAL" \
    --python-bin "$ATTACKER_PYTHON_BIN" \
    --remote-script-dir "$PROJECT_DIR_VAL/experiment_scripts" \
    || log_stage "[WARN] Saturation finder failed; continuing (non-fatal)"
fi

# Common run_experiment.sh invocation. Args: name rate size mitigation method attack_length iperf_mode
_call_run_experiment() {
  local name="$1" rate="$2" size="$3" mitigation="$4" method="$5" attack_length="$6" iperf_mode="$7"
  if [ "$mitigation" = "on" ]; then
    reset_controller_state on
  else
    reset_controller_state off
  fi
  RUN_EXPERIMENT_VERBOSE=1 bash "$SCRIPT_DIR/run_experiment.sh" \
    --name "$name" \
    --rate "$rate" \
    --size "$size" \
    --duration "$DURATION" \
    --attack-delay "$ATTACK_DELAY" \
    --attack-length "$attack_length" \
    --mitigation "$mitigation" \
    --threshold "$THRESHOLD" \
    --attack-method "$method" \
    --attack-iface "$ATTACK_IFACE" \
    --attack-python-bin "$ATTACKER_PYTHON_BIN" \
    --attack-target "$VICTIM_DATA_IP" \
    --valid-target "$VALID_TARGET_IP" \
    --switch-ips "$SWITCH_MONITOR_IPS_VAL" \
    --controller "$CONTROLLER_URL" \
    --controller-iface "$CONTROLLER_IFACE_VAL" \
    --attack-cmd-prefix "$CMD_PREFIX_ATTACK" \
    --valid-cmd-prefix "$CMD_PREFIX_VALID" \
    --iperf-server-cmd-prefix "$CMD_PREFIX_IPERF" \
    --iperf "$iperf_mode" \
    --clear-ovs off \
    --user "$USER_NAME" \
    --trusted "$TRUSTED_HOST" \
    --attacker "$ATTACKER_HOST" \
    --victim "$VICTIM_HOST" \
    --project-dir "$PROJECT_DIR_VAL" \
    2>&1 | tee -a "$RESULTS_DIR/${name}.driver.log"
}

run_main_experiment() {
  local name="$1" rate="$2" mitigation="$3" method="$4" size="$5"
  local attempt_rc=0 attempt_name="$name"

  log_stage "[INFO] Starting run: $name (duration ${DURATION}s)"
  clear_remote_ovs_flows

  set +e
  _call_run_experiment "$name" "$rate" "$size" "$mitigation" "$method" "$ATTACK_LENGTH" on
  attempt_rc=${PIPESTATUS[0]}
  set -e

  if [ "$attempt_rc" -ne 0 ] && { [ "$attempt_rc" -eq 143 ] || [ "$attempt_rc" -eq 137 ]; }; then
    log_stage "[WARN] Run $name signal-exit $attempt_rc; retrying once with iperf off"
    attempt_name="${name}_retry"
    clear_remote_ovs_flows
    set +e
    _call_run_experiment "$attempt_name" "$rate" "$size" "$mitigation" "$method" "$ATTACK_LENGTH" off
    attempt_rc=${PIPESTATUS[0]}
    set -e
  fi

  if [ "$attempt_rc" -ne 0 ]; then
    log_stage "[WARN] Run $name failed (exit $attempt_rc, last attempt: $attempt_name); continuing"
    show_run_debug_tail "$attempt_name"
    FAILED_RUNS="${FAILED_RUNS:+$FAILED_RUNS,}$attempt_name:$attempt_rc"
  elif [ "$attempt_name" != "$name" ]; then
    log_stage "[INFO] Completed run: $name (via retry: $attempt_name)"
  else
    log_stage "[INFO] Completed run: $name"
  fi
}

show_run_debug_tail() {
  local run_name="$1"
  local latest_dir
  latest_dir=$(ls -1dt "$RESULTS_DIR/${run_name}_"* 2>/dev/null | head -n 1 || true)
  if [ -z "$latest_dir" ]; then
    log_stage "[WARN] No output directory found for $run_name"
    return
  fi
  log_stage "[INFO] Debug tail from $latest_dir"
  if [ -f "$latest_dir/experiment.log" ]; then
    echo "----- experiment.log (last 60 lines) -----"
    tail -n 60 "$latest_dir/experiment.log" || true
  fi
  if [ -f "$latest_dir/collector_stderr.log" ]; then
    echo "----- collector_stderr.log (last 40 lines) -----"
    tail -n 40 "$latest_dir/collector_stderr.log" || true
  fi
  if [ -f "$latest_dir/collector_stdout.log" ]; then
    echo "----- collector_stdout.log (last 20 lines) -----"
    tail -n 20 "$latest_dir/collector_stdout.log" || true
  fi
}

run_baseline_no_attack_once() {
  local attempt="$1" iperf_mode="$2"
  log_stage "[INFO] baseline_no_attack attempt=$attempt iperf=$iperf_mode"
  clear_remote_ovs_flows
  set +e
  _call_run_experiment "baseline_no_attack" 0 256 on scapy 0 "$iperf_mode"
  local rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}

log_stage "[INFO] Running threshold tuning baseline (quiet period expected: about ${DURATION}s)"
baseline_rc=0
run_baseline_no_attack_once 1 on || baseline_rc=$?
if [ "$baseline_rc" -ne 0 ]; then
  log_stage "[WARN] baseline_no_attack attempt=1 failed with exit code $baseline_rc"
  show_run_debug_tail "baseline_no_attack"

  if [ "$baseline_rc" -eq 143 ] || [ "$baseline_rc" -eq 137 ]; then
    log_stage "[WARN] baseline_no_attack ended by signal-style code ($baseline_rc); retrying once with iperf disabled"
    baseline_rc=0
    run_baseline_no_attack_once 2 off || baseline_rc=$?
    if [ "$baseline_rc" -ne 0 ]; then
      log_stage "[WARN] baseline_no_attack attempt=2 failed with exit code $baseline_rc"
      show_run_debug_tail "baseline_no_attack"
    fi
  fi
fi

if [ "$baseline_rc" -ne 0 ]; then
  log_stage "[WARN] baseline_no_attack failed after retries; continuing full suite with threshold=$THRESHOLD"
fi
log_stage "[INFO] Completed threshold tuning baseline"

if [ "$RUN_CORE" = "on" ]; then
  log_stage "[INFO] Running core comparison suite"
  run_main_experiment "scapy_attack_mit_off" "$SCAPY_RATE" off scapy  256
  run_main_experiment "scapy_attack_mit_on"  "$SCAPY_RATE" on  scapy  256
fi

if [ "$RUN_SWEEPS" = "on" ] && [ "$RUN_RATE_SWEEP" = "on" ]; then
  log_stage "[INFO] Running scapy rate sweep"
  for r in 600 900 1200 1500 3000 5000 10000; do
    run_main_experiment "rate_${r}_scapy_mit_on" "$r" on scapy 256
  done
fi

if [ "$RUN_SWEEPS" = "on" ] && [ "$RUN_SIZE_SWEEP" = "on" ]; then
  log_stage "[INFO] Running scapy packet size sweep (rate=${SIZE_SWEEP_RATE}pps sizes=${SIZE_SWEEP_SIZES})"
  IFS=',' read -r -a SIZE_SWEEP_ARRAY <<< "$SIZE_SWEEP_SIZES"
  for sz in "${SIZE_SWEEP_ARRAY[@]}"; do
    sz="$(echo "$sz" | tr -d '[:space:]')"
    [ -n "$sz" ] || continue
    run_main_experiment "size_${sz}_scapy_mit_on" "$SIZE_SWEEP_RATE" on scapy "$sz"
  done
fi

log_stage "[INFO] Generating per-run plots"
for d in "$RESULTS_DIR"/*; do
  [ -d "$d" ] || continue
  [ -f "$d/config.json" ] || continue
  "$PYTHON_BIN" "$SCRIPT_DIR/plot_results.py" "$d" --trim-start "$TRIM_START" \
    || log_stage "[WARN] plot_results.py failed for $d; continuing (non-fatal)"
done

log_stage "[INFO] Generating cross-run summary"
"$PYTHON_BIN" "$SCRIPT_DIR/summarize_runs.py" "$RESULTS_DIR" --output "$RESULTS_DIR/summary" \
  || log_stage "[WARN] summarize_runs.py failed; continuing (non-fatal)"

"$PYTHON_BIN" "$SCRIPT_DIR/plot_rate_sweep_rtt.py" "$RESULTS_DIR" \
  || log_stage "[WARN] plot_rate_sweep_rtt.py failed; continuing (non-fatal)"

log_stage "[DONE] Full experiment suite complete"
log_stage "[DONE] Results directory: $RESULTS_DIR"
if [ -n "$FAILED_RUNS" ]; then
  log_stage "[WARN] Some runs failed but suite continued: $FAILED_RUNS"
  write_status "partial" "0" "completed with failed runs: $FAILED_RUNS"
  echo "FINAL_RESULT=partial"
else
  write_status "success" "0" "run_all_tests completed successfully"
  echo "FINAL_RESULT=success"
fi
