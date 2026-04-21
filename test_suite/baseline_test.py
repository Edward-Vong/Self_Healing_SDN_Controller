#!/usr/bin/env python3
"""
Baseline test — Normal traffic behavior for the Self-Healing SDN Controller.

Simulates legitimate client traffic using a fixed set of source MAC/IP
addresses so the controller learns host locations, installs forwarding
flows, and promotes sources to trusted status.

This produces the "Test 1: Normal traffic baseline" data for the report.

Run on node-0:
  sudo python3 baseline_test.py
"""

import os
import random
import sys
import time
import threading

from scapy.all import Ether, IP, UDP, sendp, conf

try:
    from test_suite.test_common import (
        get_attack_metrics as common_get_attack_metrics,
        get_stats as common_get_stats,
        parse_cpu_percent as common_parse_cpu_percent,
        reset_controller as common_reset_controller,
        set_mitigation_enabled as common_set_mitigation_enabled,
    )
except ModuleNotFoundError:
    from test_common import (
        get_attack_metrics as common_get_attack_metrics,
        get_stats as common_get_stats,
        parse_cpu_percent as common_parse_cpu_percent,
        reset_controller as common_reset_controller,
        set_mitigation_enabled as common_set_mitigation_enabled,
    )

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IFACE          = "eth1"
CONTROLLER_API = "http://128.110.223.3:8080"

# Fixed legitimate hosts — stable MACs/IPs the controller will learn and trust.
# Once a forwarding flow is installed for each source, subsequent packets
# bypass the controller, so steady-state PI rate approaches zero.
LEGITIMATE_HOSTS = [
    {"mac": "02:00:00:00:00:01", "ip": "10.1.0.1"},
    {"mac": "02:00:00:00:00:02", "ip": "10.1.0.2"},
    {"mac": "02:00:00:00:00:03", "ip": "10.1.0.3"},
    {"mac": "02:00:00:00:00:04", "ip": "10.1.0.4"},
    {"mac": "02:00:00:00:00:05", "ip": "10.1.0.5"},
]

DST_MAC = "ff:ff:ff:ff:ff:ff"  # Flood destination; controller learns on first hit
DST_IP  = "10.0.0.1"

# Traffic ramp — total PPS across all legitimate sources combined
RAMP_STEPS    = [10, 50, 100]
STEP_DURATION = 30    # seconds per step; long enough for flows to install and settle
POLL_INTERVAL = 2     # seconds between REST polls
CPU_STAT_KEY  = "controller_cpu_percent"

# Trust seed: packets sent per host before timed measurement begins.
# TRUST_THRESHOLD=3, so 10 packets gives a comfortable margin.
TRUST_SEED_PACKETS = 10
# ---------------------------------------------------------------------------


def get_stats():
    return common_get_stats(CONTROLLER_API)


def get_attack_metrics():
    return common_get_attack_metrics(CONTROLLER_API)


def parse_cpu_percent(stats):
    return common_parse_cpu_percent(stats, CPU_STAT_KEY)


def reset_controller():
    return common_reset_controller(CONTROLLER_API)


def ensure_mitigation_enabled():
    return common_set_mitigation_enabled(CONTROLLER_API, True)


def make_legit_packet(src_mac, src_ip):
    return (
        Ether(src=src_mac, dst=DST_MAC) /
        IP(src=src_ip, dst=DST_IP, ttl=64) /
        UDP(sport=random.randint(1024, 65535), dport=9999)
    )


def seed_trust():
    """Send TRUST_SEED_PACKETS from each host so the controller builds trust
    before the timed measurement steps begin."""
    print(f"  Seeding trust: {TRUST_SEED_PACKETS} packets x {len(LEGITIMATE_HOSTS)} hosts ...")
    for host in LEGITIMATE_HOSTS:
        pkts = [make_legit_packet(host["mac"], host["ip"]) for _ in range(TRUST_SEED_PACKETS)]
        sendp(pkts, iface=IFACE, verbose=False)
    # Give the controller time to process and update trusted_sources
    time.sleep(3)


def legit_flood(target_pps, stop_event):
    """Send legitimate traffic round-robin across all hosts at target_pps total."""
    host_count = len(LEGITIMATE_HOSTS)
    interval = 1.0 / target_pps
    idx = 0
    next_send = time.perf_counter()

    while not stop_event.is_set():
        host = LEGITIMATE_HOSTS[idx % host_count]
        pkt = make_legit_packet(host["mac"], host["ip"])
        sendp(pkt, iface=IFACE, verbose=False)
        idx += 1

        next_send += interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            next_send = time.perf_counter()


def run_step(target_pps):
    """
    Send legitimate traffic at target_pps for STEP_DURATION seconds.
    Returns (avg_pi_rate, peak_pi_rate, avg_cpu, peak_cpu,
             false_positive, trusted_count, final_known_hosts).
    """
    stop_event = threading.Event()
    flood_thread = threading.Thread(
        target=legit_flood, args=(target_pps, stop_event), daemon=True
    )
    flood_thread.start()

    rates = []
    cpu_rates = []
    false_positive = False
    known_hosts = 0
    step_start = time.time()

    while time.time() - step_start < STEP_DURATION:
        stats = get_stats()
        if stats:
            rate   = stats.get("packet_in_rate", 0)
            cpu    = parse_cpu_percent(stats)
            attack = stats.get("attack_detected", False)
            known_hosts = stats.get("known_hosts", 0)

            rates.append(rate)
            if cpu is not None:
                cpu_rates.append(cpu)

            if attack:
                false_positive = True
                print(f"    target={target_pps} pps  pi_rate={rate}/s  cpu={cpu}%  "
                      f"known_hosts={known_hosts}  [!! FALSE POSITIVE]")
            else:
                print(f"    target={target_pps} pps  pi_rate={rate}/s  cpu={cpu}%  "
                      f"known_hosts={known_hosts}")

        time.sleep(POLL_INTERVAL)

    stop_event.set()
    flood_thread.join(timeout=3)

    metrics = get_attack_metrics()
    trusted_count = 0
    if metrics:
        trusted_count = len(metrics.get("mitigation", {}).get("trusted_sources", []))

    avg_pi   = round(sum(rates) / len(rates), 2) if rates else 0
    peak_pi  = round(max(rates), 2)              if rates else 0
    avg_cpu  = round(sum(cpu_rates) / len(cpu_rates), 2) if cpu_rates else None
    peak_cpu = round(max(cpu_rates), 2)                  if cpu_rates else None

    return avg_pi, peak_pi, avg_cpu, peak_cpu, false_positive, trusted_count, known_hosts


def main():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ERROR: Scapy sendp() requires raw-socket privileges.")
        print("       Run with: sudo python3.8 ./test_suite/baseline_test.py")
        sys.exit(1)

    conf.iface = IFACE

    print(f"Interface        : {IFACE}")
    print(f"Controller API   : {CONTROLLER_API}")
    print(f"Traffic steps    : {RAMP_STEPS} pps")
    print(f"Step duration    : {STEP_DURATION}s")
    print(f"Legitimate hosts : {len(LEGITIMATE_HOSTS)} fixed MAC/IP sources")
    print(f"Mitigation       : ENABLED (confirming no false positives under normal load)")
    print()

    stats = get_stats()
    if stats is None:
        print("ERROR: Cannot reach Ryu REST API. Is the controller running?")
        sys.exit(1)

    if not stats.get("mitigation_enabled", True):
        print("  Mitigation was disabled — re-enabling for baseline test ...")
        if not ensure_mitigation_enabled():
            print("ERROR: Could not enable mitigation.")
            sys.exit(2)

    print(f"Controller reachable — uptime={stats.get('uptime_seconds')}s  "
          f"threshold={stats.get('packet_in_threshold')} PI/s")
    print()

    if not reset_controller():
        print("ERROR: Could not reset controller state — aborting.")
        sys.exit(3)
    time.sleep(1)

    seed_trust()

    metrics = get_attack_metrics()
    if metrics:
        trusted = metrics.get("mitigation", {}).get("trusted_sources", [])
        print(f"  Trust seeded — {len(trusted)}/{len(LEGITIMATE_HOSTS)} hosts trusted: {trusted}")
    print()

    rows = []
    top_hdr = (f"{'Target PPS':>12}  {'Avg PI/s':>10}  {'Avg CPU%':>9}  "
               f"{'Trusted':>8}  {'Hosts':>6}")
    top_sep = "-" * len(top_hdr)
    print(top_hdr)
    print(top_sep)

    for target_pps in RAMP_STEPS:
        print(f"\n  Step: {target_pps} pps ({STEP_DURATION}s window) ...")
        avg_pi, peak_pi, avg_cpu, peak_cpu, false_pos, trusted_count, known_hosts = run_step(target_pps)

        avg_cpu_s  = f"{avg_cpu}%"  if avg_cpu  is not None else "n/a"
        peak_cpu_s = f"{peak_cpu}%" if peak_cpu is not None else "n/a"
        attack_str = "YES [!]" if false_pos else "No"

        print(f"  -> avg={avg_pi}/s  peak={peak_pi}/s  avg_cpu={avg_cpu_s}  "
              f"peak_cpu={peak_cpu_s}  trusted={trusted_count}/{len(LEGITIMATE_HOSTS)}  "
              f"attack_triggered={attack_str}")

        rows.append({
            "target_pps":       target_pps,
            "avg_pi_rate":      avg_pi,
            "peak_pi_rate":     peak_pi,
            "avg_cpu_percent":  avg_cpu,
            "peak_cpu_percent": peak_cpu,
            "known_hosts":      known_hosts,
            "trusted_sources":  trusted_count,
            "false_positive":   false_pos,
        })

        time.sleep(5)

    summary_hdr = (f"{'Target PPS':>12}  {'Avg PI/s':>10}  {'Peak PI/s':>10}  "
                   f"{'Avg CPU%':>9}  {'Peak CPU%':>10}  {'Trusted':>8}  {'Hosts':>6}")
    summary_sep = "-" * len(summary_hdr)
    print("\n" + "=" * len(summary_hdr))
    print(summary_hdr)
    print(summary_sep)
    for r in rows:
        avg_c  = r["avg_cpu_percent"]  if r["avg_cpu_percent"]  is not None else "n/a"
        peak_c = r["peak_cpu_percent"] if r["peak_cpu_percent"] is not None else "n/a"
        print(f"{r['target_pps']:>12}  {r['avg_pi_rate']:>10}  {r['peak_pi_rate']:>10}  "
              f"{avg_c:>9}  {peak_c:>10}  {r['trusted_sources']:>8}  "
              f"{r['known_hosts']:>6}")
    print("=" * len(summary_hdr))

if __name__ == "__main__":
    main()
