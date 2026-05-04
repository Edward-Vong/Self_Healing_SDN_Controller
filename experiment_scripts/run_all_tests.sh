#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SWITCHES_CONF="$SCRIPT_DIR/switches.conf"

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
TRUSTED_DATA_IP="${TRUSTED_DATA_IP:-10.10.10.1}"
ATTACKER_DATA_IP="${ATTACKER_DATA_IP:-10.10.10.2}"
VICTIM_DATA_IP="${VICTIM_DATA_IP:-10.10.10.3}"

CONTROLLER_URL="${CONTROLLER:-http://127.0.0.1:8080}"
CONTROLLER_IFACE_VAL="${CONTROLLER_IFACE:-eth0}"
PROJECT_DIR_VAL="${PROJECT_DIR:-$ROOT_DIR}"

# Experiment defaults.
RUN_BASELINE_CONTROL=on
RUN_SATURATION=on
RUN_CORE=on
RUN_SWEEPS=on
CLEAR_OVS_MODE="off"

DURATION=180
ATTACK_DELAY=30
ATTACK_LENGTH=90
ATTACK_IFACE="ovs-lan2"
SCAPY_RATE=1200
HPING_RATE=10000
THRESHOLD_OVERRIDE=""

log_stage() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

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
  --victim-data-ip IP          Victim dataplane IP (default: $VICTIM_DATA_IP)
  --project-dir DIR            Repo path on remote nodes (default from switches.conf or local)
  --controller-iface IFACE     Controller interface for utilization metrics
  --attack-iface IFACE         Attacker egress iface for scapy (default: $ATTACK_IFACE)
  --duration SEC               Duration for main runs (default: $DURATION)
  --attack-delay SEC           Delay before attack starts (default: $ATTACK_DELAY)
  --attack-length SEC          Attack duration inside each run (default: $ATTACK_LENGTH)
  --hping-rate PPS             Hping label rate (default: $HPING_RATE)
  --scapy-rate PPS             Scapy PPS (default: $SCAPY_RATE)
  --threshold N                Skip baseline threshold extraction and use N
  --skip-baseline-control      Skip baseline collect_metrics stage
  --skip-saturation            Skip saturation finder stage
  --skip-core                  Skip core 3 comparison runs
  --skip-sweeps                Skip rate and size sweeps
  --clear-ovs MODE             on|off|auto for run_experiment.sh (default: $CLEAR_OVS_MODE)
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
    --project-dir) PROJECT_DIR_VAL="$2"; shift 2 ;;
    --controller-iface) CONTROLLER_IFACE_VAL="$2"; shift 2 ;;
    --attack-iface) ATTACK_IFACE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --attack-delay) ATTACK_DELAY="$2"; shift 2 ;;
    --attack-length) ATTACK_LENGTH="$2"; shift 2 ;;
    --hping-rate) HPING_RATE="$2"; shift 2 ;;
    --scapy-rate) SCAPY_RATE="$2"; shift 2 ;;
    --threshold) THRESHOLD_OVERRIDE="$2"; shift 2 ;;
    --skip-baseline-control) RUN_BASELINE_CONTROL=off; shift ;;
    --skip-saturation) RUN_SATURATION=off; shift ;;
    --skip-core) RUN_CORE=off; shift ;;
    --skip-sweeps) RUN_SWEEPS=off; shift ;;
    --clear-ovs) CLEAR_OVS_MODE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

require_non_empty() {
  local name="$1"
  local value="$2"
  if [ -z "$value" ]; then
    echo "[ERROR] Missing required value: $name" >&2
    exit 2
  fi
}

is_probable_dataplane_ip() {
  case "$1" in
    10.10.10.*) return 0 ;;
    *) return 1 ;;
  esac
}

require_non_empty "USER (SSH username)" "$USER_NAME"
require_non_empty "TRUSTED host" "$TRUSTED_HOST"
require_non_empty "ATTACKER host" "$ATTACKER_HOST"
require_non_empty "VICTIM host" "$VICTIM_HOST"
require_non_empty "VICTIM data IP" "$VICTIM_DATA_IP"

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

RESULTS_DIR="$ROOT_DIR/results"
mkdir -p "$RESULTS_DIR"

log_stage "[INFO] Verifying SSH connectivity"
$SSH_TRUSTED "hostname"
$SSH_ATTACKER "hostname"
$SSH_VICTIM "hostname"

log_stage "[INFO] Verifying controller API at $CONTROLLER_URL"
curl -fsS "$CONTROLLER_URL/stats" >/dev/null

log_stage "[INFO] Ensuring packetin_attack.py exists on attacker"
$SSH_ATTACKER "mkdir -p '$PROJECT_DIR_VAL/experiment_scripts'"
scp $SCP_OPTS "$SCRIPT_DIR/packetin_attack.py" "$USER_NAME@$ATTACKER_HOST:$PROJECT_DIR_VAL/experiment_scripts/packetin_attack.py" >/dev/null

THRESHOLD="${THRESHOLD_OVERRIDE}"

if [ "$RUN_BASELINE_CONTROL" = "on" ] && [ -z "$THRESHOLD" ]; then
  log_stage "[INFO] Running baseline control collection (about 180s)"
  $SSH_VICTIM "nohup iperf -s >/tmp/iperf_server_control.log 2>&1 < /dev/null &" || true
  $SSH_TRUSTED "nohup ping -i 0.5 -w 180 '$VICTIM_DATA_IP' >/tmp/ping_control.log 2>&1 < /dev/null &"
  $SSH_TRUSTED "nohup iperf -c '$VICTIM_DATA_IP' -t 180 >/tmp/iperf_control.log 2>&1 < /dev/null &"

  python3 "$SCRIPT_DIR/collect_metrics.py" \
    --duration 180 \
    --out "$RESULTS_DIR/control_normal_traffic" \
    --controller "$CONTROLLER_URL" \
    --iface "$CONTROLLER_IFACE_VAL" \
    --baseline

  THRESHOLD="$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/control_normal_traffic/baseline_summary.json')); print(int((d['packet_in_rate']['max'] or 0) * 3))")"
  log_stage "[INFO] Derived threshold=$THRESHOLD"
elif [ -z "$THRESHOLD" ]; then
  THRESHOLD=300
  log_stage "[WARN] Baseline skipped and no threshold override provided; using fallback threshold=$THRESHOLD"
else
  log_stage "[INFO] Using provided threshold=$THRESHOLD"
fi

if [ "$RUN_SATURATION" = "on" ]; then
  log_stage "[INFO] Running saturation finder"
  python3 "$SCRIPT_DIR/saturation_finder.py" \
    --controller "$CONTROLLER_URL" \
    --out "$RESULTS_DIR/saturation_analysis" \
    --target "$VICTIM_DATA_IP" \
    --iface "$ATTACK_IFACE" \
    --attack-method scapy \
    --cmd-prefix "$SSH_ATTACKER" \
    --step-duration 30 \
    --rtt-threshold-ms 50 \
    --loss-threshold-percent 5 \
    --rates 1000,5000,10000,20000,50000
fi

run_main_experiment() {
  local name="$1"
  local rate="$2"
  local mitigation="$3"
  local method="$4"
  local size="$5"

  log_stage "[INFO] Starting run: $name (duration ${DURATION}s + setup/recovery)."
  log_stage "[INFO] Reminder: clear OVS flows manually on each switch host if needed before this run."

  bash "$SCRIPT_DIR/run_experiment.sh" \
    --name "$name" \
    --rate "$rate" \
    --size "$size" \
    --duration "$DURATION" \
    --attack-delay "$ATTACK_DELAY" \
    --attack-length "$ATTACK_LENGTH" \
    --mitigation "$mitigation" \
    --threshold "$THRESHOLD" \
    --attack-method "$method" \
    --attack-iface "$ATTACK_IFACE" \
    --attack-target "$VICTIM_DATA_IP" \
    --valid-target "$VICTIM_DATA_IP" \
    --controller "$CONTROLLER_URL" \
    --controller-iface "$CONTROLLER_IFACE_VAL" \
    --attack-cmd-prefix "$CMD_PREFIX_ATTACK" \
    --valid-cmd-prefix "$CMD_PREFIX_VALID" \
    --iperf-server-cmd-prefix "$CMD_PREFIX_IPERF" \
    --iperf on \
    --clear-ovs "$CLEAR_OVS_MODE" \
    --user "$USER_NAME" \
    --trusted "$TRUSTED_HOST" \
    --attacker "$ATTACKER_HOST" \
    --victim "$VICTIM_HOST" \
    --project-dir "$PROJECT_DIR_VAL"

  log_stage "[INFO] Completed run: $name"
}

log_stage "[INFO] Running threshold tuning baseline (quiet period expected: about ${DURATION}s)"
bash "$SCRIPT_DIR/run_experiment.sh" \
  --name baseline_no_attack \
  --rate 0 \
  --size 64 \
  --duration "$DURATION" \
  --attack-delay "$ATTACK_DELAY" \
  --attack-length 0 \
  --mitigation on \
  --threshold "$THRESHOLD" \
  --attack-method hping3 \
  --attack-target "$VICTIM_DATA_IP" \
  --valid-target "$VICTIM_DATA_IP" \
  --controller "$CONTROLLER_URL" \
  --controller-iface "$CONTROLLER_IFACE_VAL" \
  --attack-cmd-prefix "$CMD_PREFIX_ATTACK" \
  --valid-cmd-prefix "$CMD_PREFIX_VALID" \
  --iperf-server-cmd-prefix "$CMD_PREFIX_IPERF" \
  --iperf on \
  --clear-ovs "$CLEAR_OVS_MODE" \
  --user "$USER_NAME" \
  --trusted "$TRUSTED_HOST" \
  --attacker "$ATTACKER_HOST" \
  --victim "$VICTIM_HOST" \
  --project-dir "$PROJECT_DIR_VAL"
log_stage "[INFO] Completed threshold tuning baseline"

if [ "$RUN_CORE" = "on" ]; then
  log_stage "[INFO] Running core comparison suite"
  run_main_experiment "hping_attack_mit_off" "$HPING_RATE" off hping3 64
  run_main_experiment "hping_attack_mit_on" "$HPING_RATE" on hping3 64
  run_main_experiment "scapy_attack_mit_on" "$SCAPY_RATE" on scapy 64
fi

if [ "$RUN_SWEEPS" = "on" ]; then
  log_stage "[INFO] Running scapy rate sweep"
  for r in 600 900 1200 1500 3000 5000 10000; do
    run_main_experiment "rate_${r}_scapy_mit_on" "$r" on scapy 64
  done

  log_stage "[INFO] Running scapy packet size sweep"
  for s in 64 256 512; do
    run_main_experiment "size_${s}_scapy_mit_on" "$SCAPY_RATE" on scapy "$s"
  done
fi

log_stage "[INFO] Generating per-run plots"
for d in "$RESULTS_DIR"/*; do
  [ -d "$d" ] || continue
  [ -f "$d/config.json" ] || continue
  python3 "$SCRIPT_DIR/plot_results.py" "$d"
done

log_stage "[INFO] Generating cross-run summary"
python3 "$SCRIPT_DIR/summarize_runs.py" "$RESULTS_DIR" --output "$RESULTS_DIR/summary"

log_stage "[DONE] Full experiment suite complete"
log_stage "[DONE] Results directory: $RESULTS_DIR"
