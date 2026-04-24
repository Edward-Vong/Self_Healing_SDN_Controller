#!/usr/bin/env python3
"""
Simplified baseline test for normal controller behavior.

Flow:
1) Ensure controller is reachable and mitigation is enabled.
2) Reset controller state.
3) For each PPS step, run benign hping3 UDP traffic for a fixed window.
4) Sample packet-in rate, CPU, false-positive state, and mitigation drop signals.
"""

import os
import subprocess
import sys
import threading
import time

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


IFACE = "eth1"
CONTROLLER_API = "http://128.110.223.3:8080"
DST_IP = "10.0.0.1"
CPU_STAT_KEY = "controller_cpu_percent"
RAMP_STEPS = [10, 50, 100]
STEP_DURATION = 30
POLL_INTERVAL = 2
HPING3_BIN = "hping3"
HPING3_DPORT = 9999
HPING3_DLEN = 64


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


def _hping3_interval_arg(pps):
    # hping3 non-flood mode uses interval syntax: -i u<micros>
    micros = max(1, int(round(1000000.0 / float(max(1, pps)))))
    return f"u{micros}"


def run_hping3_rate(pps, stop_event):
    cmd = [
        HPING3_BIN,
        "--udp",
        "-p",
        str(HPING3_DPORT),
        "-d",
        str(HPING3_DLEN),
        "-i",
        _hping3_interval_arg(pps),
        "--interface",
        IFACE,
        DST_IP,
    ]

    print(f"    hping3 cmd: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        print(f"ERROR: '{HPING3_BIN}' not found. Install hping3 and retry.")
        stop_event.wait()
        return

    stop_event.wait()
    proc.terminate()
    try:
        proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()


def run_step(target_pps):
    stop_event = threading.Event()
    sender = threading.Thread(target=run_hping3_rate, args=(target_pps, stop_event), daemon=True)
    sender.start()

    rates = []
    cpu_rates = []
    false_positive = False
    known_hosts = 0
    saw_rate_limited = False
    saw_escalated = False
    start = time.time()

    while time.time() - start < STEP_DURATION:
        stats = get_stats() or {}
        metrics = get_attack_metrics() or {}

        rate = stats.get("packet_in_rate", 0)
        cpu = parse_cpu_percent(stats)
        attack = bool(stats.get("attack_detected", False))
        known_hosts = stats.get("known_hosts", 0)

        mitigation = metrics.get("mitigation", {}) if isinstance(metrics, dict) else {}
        rl_map = mitigation.get("rate_limited_ports", {}) if isinstance(mitigation, dict) else {}
        esc_map = mitigation.get("escalated_ports", {}) if isinstance(mitigation, dict) else {}
        rl_count = sum(len(v) for v in rl_map.values() if isinstance(v, list))
        esc_count = sum(len(v) for v in esc_map.values() if isinstance(v, list))

        saw_rate_limited = saw_rate_limited or rl_count > 0
        saw_escalated = saw_escalated or esc_count > 0

        rates.append(rate)
        if cpu is not None:
            cpu_rates.append(cpu)

        if attack:
            false_positive = True
            print(
                f"    target={target_pps} pps  pi_rate={rate}/s  cpu={cpu}%  "
                f"known_hosts={known_hosts}  rl_ports={rl_count}  esc_ports={esc_count}  "
                "[!! FALSE POSITIVE]"
            )
        else:
            print(
                f"    target={target_pps} pps  pi_rate={rate}/s  cpu={cpu}%  "
                f"known_hosts={known_hosts}  rl_ports={rl_count}  esc_ports={esc_count}"
            )

        time.sleep(POLL_INTERVAL)

    stop_event.set()
    sender.join(timeout=3)

    avg_pi = round(sum(rates) / len(rates), 2) if rates else 0
    peak_pi = round(max(rates), 2) if rates else 0
    avg_cpu = round(sum(cpu_rates) / len(cpu_rates), 2) if cpu_rates else None
    peak_cpu = round(max(cpu_rates), 2) if cpu_rates else None

    return {
        "target_pps": target_pps,
        "avg_pi_rate": avg_pi,
        "peak_pi_rate": peak_pi,
        "avg_cpu_percent": avg_cpu,
        "peak_cpu_percent": peak_cpu,
        "known_hosts": known_hosts,
        "false_positive": false_positive,
        "saw_rate_limited": saw_rate_limited,
        "saw_escalated": saw_escalated,
    }


def main():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ERROR: hping3 requires raw-socket privileges.")
        print("       Run with: sudo python3 ./test_suite/baseline_test.py")
        sys.exit(1)

    print(f"Interface      : {IFACE}")
    print(f"Controller API : {CONTROLLER_API}")
    print(f"Traffic steps  : {RAMP_STEPS} pps")
    print(f"Step duration  : {STEP_DURATION}s")
    print("Backend        : hping3 UDP fixed-rate")
    print()

    stats = get_stats()
    if stats is None:
        print("ERROR: Cannot reach Ryu REST API. Is the controller running?")
        sys.exit(1)

    if not stats.get("mitigation_enabled", True):
        print("Mitigation is disabled; enabling it for baseline test...")
        if not ensure_mitigation_enabled():
            print("ERROR: Could not enable mitigation.")
            sys.exit(2)

    if not reset_controller():
        print("ERROR: Could not reset controller state.")
        sys.exit(3)

    time.sleep(1)

    rows = []
    print(f"{'Target PPS':>12}  {'Avg PI/s':>10}  {'Avg CPU%':>9}  {'Hosts':>6}  {'Drops?':>8}")
    print("-" * 60)

    for pps in RAMP_STEPS:
        print(f"\n  Step: {pps} pps ({STEP_DURATION}s window) ...")
        row = run_step(pps)
        rows.append(row)

        avg_cpu = row["avg_cpu_percent"]
        peak_cpu = row["peak_cpu_percent"]
        avg_cpu_s = f"{avg_cpu}%" if avg_cpu is not None else "n/a"
        peak_cpu_s = f"{peak_cpu}%" if peak_cpu is not None else "n/a"
        attack_s = "YES [!]" if row["false_positive"] else "No"
        drops_s = "YES" if (row["saw_rate_limited"] or row["saw_escalated"]) else "No"

        print(
            f"  -> avg={row['avg_pi_rate']}/s  peak={row['peak_pi_rate']}/s  "
            f"avg_cpu={avg_cpu_s}  peak_cpu={peak_cpu_s}  "
            f"attack_triggered={attack_s}  drops={drops_s}"
        )

        time.sleep(2)

    header = (
        f"{'Target PPS':>12}  {'Avg PI/s':>10}  {'Peak PI/s':>10}  "
        f"{'Avg CPU%':>9}  {'Peak CPU%':>10}  {'Hosts':>6}  {'Drops?':>8}"
    )
    print("\n" + "=" * len(header))
    print(header)
    print("-" * len(header))
    for row in rows:
        avg_c = row["avg_cpu_percent"] if row["avg_cpu_percent"] is not None else "n/a"
        peak_c = row["peak_cpu_percent"] if row["peak_cpu_percent"] is not None else "n/a"
        drops = "YES" if (row["saw_rate_limited"] or row["saw_escalated"]) else "No"
        print(
            f"{row['target_pps']:>12}  {row['avg_pi_rate']:>10}  {row['peak_pi_rate']:>10}  "
            f"{avg_c:>9}  {peak_c:>10}  {row['known_hosts']:>6}  {drops:>8}"
        )
    print("=" * len(header))


if __name__ == "__main__":
    main()
