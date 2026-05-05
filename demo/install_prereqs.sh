#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SWITCHES_CONF="$ROOT_DIR/experiment_scripts/switches.conf"

if [ -f "$SWITCHES_CONF" ]; then
  # shellcheck disable=SC1090
  . "$SWITCHES_CONF"
fi

USER_NAME="${USER:-}"
TRUSTED_HOST="${TRUSTED:-}"
ATTACKER_HOST="${ATTACKER:-}"
VICTIM_HOST="${VICTIM:-}"
ATTACKER_PYTHON_BIN="${ATTACKER_PYTHON_BIN:-python3.8}"

for n in USER_NAME TRUSTED_HOST ATTACKER_HOST VICTIM_HOST; do
  if [ -z "${!n}" ]; then
    echo "[ERROR] Missing required config: $n (check experiment_scripts/switches.conf)" >&2
    exit 2
  fi
done

run_remote() {
  local host="$1"
  local cmd="$2"
  echo "[INFO] $host :: $cmd"
  ssh -n -T -o BatchMode=yes -o ConnectTimeout=8 "$USER_NAME@$host" "$cmd"
}

echo "[INFO] Installing common tools on trusted/attacker/victim"
for host in "$TRUSTED_HOST" "$ATTACKER_HOST" "$VICTIM_HOST"; do
  run_remote "$host" "sudo apt-get update && sudo apt-get install -y iputils-ping arping ethtool iperf hping3"
done

echo "[INFO] Installing Scapy on attacker with $ATTACKER_PYTHON_BIN"
run_remote "$ATTACKER_HOST" "sudo $ATTACKER_PYTHON_BIN -m pip install --upgrade pip scapy"

echo "[INFO] Verifying installs"
run_remote "$ATTACKER_HOST" "which hping3 && sudo $ATTACKER_PYTHON_BIN -c 'import scapy; print(scapy.__version__)'"
run_remote "$TRUSTED_HOST" "which iperf && which arping && which ethtool"
run_remote "$VICTIM_HOST" "which iperf && which arping && which ethtool"

echo "[DONE] Prerequisite install complete"
