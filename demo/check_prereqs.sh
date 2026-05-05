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
CONTROLLER_URL="${CONTROLLER:-http://127.0.0.1:8080}"
ATTACK_IFACE_VAL="${ATTACK_IFACE:-eth1}"
ATTACKER_PYTHON_BIN="${ATTACKER_PYTHON_BIN:-python3.8}"
ATTACK_TARGET="${VICTIM_DATA_IP:-10.10.3.2}"
VALID_TARGET="${VALID_TARGET_IP:-10.10.2.2}"

for n in USER_NAME TRUSTED_HOST ATTACKER_HOST VICTIM_HOST; do
  if [ -z "${!n}" ]; then
    echo "[ERROR] Missing required config: $n (check experiment_scripts/switches.conf)" >&2
    exit 2
  fi
done

SSH_OPTS="-n -T -o BatchMode=yes -o ConnectTimeout=8"
fail=0

ok() { echo "[OK]  $*"; }
bad() { echo "[FAIL] $*"; fail=$((fail+1)); }

run() {
  local host="$1"
  local cmd="$2"
  ssh $SSH_OPTS "$USER_NAME@$host" "$cmd"
}

echo "[INFO] Checking controller API"
if curl -fsS "$CONTROLLER_URL/stats" >/dev/null 2>&1; then ok "$CONTROLLER_URL/stats"; else bad "controller API unreachable"; fi

echo "[INFO] Checking SSH"
for h in "$TRUSTED_HOST" "$ATTACKER_HOST" "$VICTIM_HOST"; do
  if run "$h" "hostname" >/dev/null 2>&1; then ok "ssh $h"; else bad "ssh $h"; fi
done

echo "[INFO] Checking binaries"
if run "$ATTACKER_HOST" "which hping3 >/dev/null 2>&1"; then ok "attacker hping3"; else bad "attacker hping3 missing"; fi
if run "$ATTACKER_HOST" "sudo -n $ATTACKER_PYTHON_BIN -c 'import scapy'" >/dev/null 2>&1; then ok "attacker scapy ($ATTACKER_PYTHON_BIN)"; else bad "attacker scapy missing for sudo $ATTACKER_PYTHON_BIN"; fi
if run "$TRUSTED_HOST" "which iperf >/dev/null 2>&1"; then ok "trusted iperf"; else bad "trusted iperf missing"; fi
if run "$VICTIM_HOST" "which iperf >/dev/null 2>&1"; then ok "victim iperf"; else bad "victim iperf missing"; fi

echo "[INFO] Checking attacker interface"
if run "$ATTACKER_HOST" "ip link show '$ATTACK_IFACE_VAL' >/dev/null 2>&1"; then
  st=$(run "$ATTACKER_HOST" "cat /sys/class/net/$ATTACK_IFACE_VAL/operstate 2>/dev/null || echo unknown")
  ok "attacker iface $ATTACK_IFACE_VAL exists (operstate=$st)"
  if [ "$st" = "down" ] || [ "$st" = "dormant" ] || [ "$st" = "notpresent" ]; then
    bad "attacker iface $ATTACK_IFACE_VAL not up"
  fi
else
  bad "attacker iface $ATTACK_IFACE_VAL missing"
fi

echo "[INFO] Checking dataplane ARP"
if run "$ATTACKER_HOST" "arping -I $ATTACK_IFACE_VAL -c 2 $ATTACK_TARGET >/tmp/arp_demo_attack.log 2>&1" && run "$ATTACKER_HOST" "grep -q 'Received [1-9]' /tmp/arp_demo_attack.log"; then
  ok "attacker -> victim ARP ($ATTACK_IFACE_VAL to $ATTACK_TARGET)"
else
  bad "attacker -> victim ARP failed"
  run "$ATTACKER_HOST" "tail -5 /tmp/arp_demo_attack.log" || true
fi

if run "$TRUSTED_HOST" "arping -I eth1 -c 2 $VALID_TARGET >/tmp/arp_demo_valid.log 2>&1" && run "$TRUSTED_HOST" "grep -q 'Received [1-9]' /tmp/arp_demo_valid.log"; then
  ok "trusted -> victim ARP (eth1 to $VALID_TARGET)"
else
  bad "trusted -> victim ARP failed"
  run "$TRUSTED_HOST" "tail -5 /tmp/arp_demo_valid.log" || true
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "[DONE] All prereq checks passed"
else
  echo "[DONE] $fail check(s) failed"
  exit 1
fi
