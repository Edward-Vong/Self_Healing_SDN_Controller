#!/usr/bin/env python3
"""
Saturation test for the Self-Healing SDN Controller.

Sends Packet_In-forcing traffic at increasing PPS levels and records
the controller's packet_in_rate at each step.

For each step, traffic keeps running until the measured Packet_In rate
reaches the target PPS and stays there for STEP_DURATION seconds.
If that cannot happen within STEP_TIMEOUT seconds, the test stops.

From the OVS output on node-0:
  - Bridge : ovs-lan1
  - Ports  : eth1, eth2
  - Controller : tcp:128.110.223.3:6653  (Ryu REST on port 8080)

Run on node-0 (or node-1/node-2), e.g.:
  sudo python3 traffic_test.py

Requires: scapy, requests
  pip3 install scapy requests
"""

import csv
import random
import sys
import time
import threading

import requests
from scapy.all import Ether, IP, UDP, sendp, conf

# ---------------------------------------------------------------------------
# Configuration — edit these to match your setup
# ---------------------------------------------------------------------------
IFACE          = "eth1"                    # data-plane interface facing OVS
CONTROLLER_API = "http://128.110.223.3:8080"  # Ryu REST API

# PPS ladder — each step must reach its target rate and hold it for
# STEP_DURATION seconds before moving to the next step.
RAMP_STEPS     = [50, 100, 250, 500, 1000, 2000, 5000, 10000]
STEP_DURATION  = 10   # seconds rate must stay at target once reached
STEP_TIMEOUT   = 60   # abort current/overall test if target not reached in this time
RATE_TOLERANCE = 0.95 # consider target reached at >= target_pps * RATE_TOLERANCE
POLL_INTERVAL  = 2    # seconds between REST polls within a step
OUTPUT_CSV     = "saturation_results.csv"

# Destination — unknown dst MAC forces every packet to hit the controller
DST_MAC = "ff:ff:ff:ff:ff:ff"
DST_IP  = "10.0.0.1"
# ---------------------------------------------------------------------------


def get_stats():
    try:
        r = requests.get(CONTROLLER_API + "/stats", timeout=4)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"  [REST] /stats failed: {e}")
        return None


def set_threshold(value):
    try:
        requests.post(CONTROLLER_API + "/config/threshold",
                      json={"threshold": value}, timeout=4)
    except requests.RequestException:
        pass


def reset_controller():
    try:
        requests.post(CONTROLLER_API + "/config/reset", timeout=4)
    except requests.RequestException:
        pass


def make_packet():
    """Random source MAC/IP so every packet misses the flow table -> Packet_In."""
    src_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5)
    )
    src_ip = "10.%d.%d.%d" % (
        random.randint(1, 254),
        random.randint(1, 254),
        random.randint(1, 254),
    )
    return (
        Ether(src=src_mac, dst=DST_MAC) /
        IP(src=src_ip, dst=DST_IP, ttl=64) /
        UDP(sport=random.randint(1024, 65535), dport=9999)
    )


def flood(target_pps, stop_event):
    """Continuously send packets as close to target_pps as possible."""
    interval = 1.0 / target_pps
    sent = 0
    next_send = time.perf_counter()

    while not stop_event.is_set():
        sendp(make_packet(), iface=IFACE, verbose=False)
        sent += 1

        next_send += interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            # If we fall behind at high PPS, resync to avoid runaway drift.
            next_send = time.perf_counter()

    return sent


def run_step(target_pps):
    """
    Flood at target_pps until measured rate reaches the tolerated target and
    remains there for STEP_DURATION seconds, or until STEP_TIMEOUT is exceeded.
    Returns (avg_pi_rate, peak_pi_rate, reached_target, time_to_reach, hold_time, required_rate).
    """
    stop_event = threading.Event()
    flood_thread = threading.Thread(
        target=flood, args=(target_pps, stop_event), daemon=True
    )
    flood_thread.start()

    rates = []
    required_rate = target_pps * RATE_TOLERANCE
    step_start = time.time()
    stable_since = None
    reached_target = False
    time_to_reach = None
    hold_time = 0.0

    while True:
        now = time.time()
        elapsed = now - step_start

        if elapsed > STEP_TIMEOUT:
            break

        stats = get_stats()
        if stats:
            rate = stats.get("packet_in_rate", 0)
            rates.append(rate)
            print(f"    target={target_pps} pps  measured pi_rate={rate}/s")

            if rate >= required_rate:
                if stable_since is None:
                    stable_since = now
                    reached_target = True
                    time_to_reach = now - step_start

                hold_time = now - stable_since
                if hold_time >= STEP_DURATION:
                    break
            else:
                stable_since = None
                hold_time = 0.0

        time.sleep(POLL_INTERVAL)

    stop_event.set()
    flood_thread.join(timeout=3)

    avg  = round(sum(rates) / len(rates), 2) if rates else 0
    peak = round(max(rates), 2)             if rates else 0
    return avg, peak, reached_target and hold_time >= STEP_DURATION, round(time_to_reach, 2) if time_to_reach is not None else None, round(hold_time, 2), round(required_rate, 2)


def main():
    conf.iface = IFACE

    print(f"Interface      : {IFACE}")
    print(f"Controller API : {CONTROLLER_API}")
    print(f"Ramp steps     : {RAMP_STEPS} pps")
    print(f"Rate tolerance : {int(RATE_TOLERANCE * 100)}% of target")
    print(f"Hold duration  : {STEP_DURATION}s at target")
    print(f"Step timeout   : {STEP_TIMEOUT}s max to reach/hold target")
    print()

    # Verify controller is up
    stats = get_stats()
    if stats is None:
        print("ERROR: Cannot reach Ryu REST API. Is the controller running?")
        sys.exit(1)
    print(f"Controller reachable — uptime={stats.get('uptime_seconds')}s")
    print()

    # Disable auto-mitigation so it doesn't interfere with measurements
    set_threshold(999999)
    reset_controller()
    time.sleep(1)

    rows = []
    print(f"{'Target PPS':>12}  {'Avg PI Rate':>12}  {'Peak PI Rate':>13}")
    print("-" * 42)

    for target_pps in RAMP_STEPS:
        print(f"\n  Step: {target_pps} pps (must hold >= target for {STEP_DURATION}s) ...")
        avg_rate, peak_rate, reached_hold, time_to_reach, hold_time, required_rate = run_step(target_pps)

        rows.append({
            "target_pps":   target_pps,
            "required_pi_rate": required_rate,
            "avg_pi_rate":  avg_rate,
            "peak_pi_rate": peak_rate,
            "reached_and_held": reached_hold,
            "time_to_reach_s": time_to_reach,
            "hold_time_s": hold_time,
        })
        if reached_hold:
            print(f"  -> avg={avg_rate}/s  peak={peak_rate}/s  reached_in={time_to_reach}s  required>={required_rate}/s")
        else:
            print(f"  -> avg={avg_rate}/s  peak={peak_rate}/s  FAILED to hold >= {required_rate}/s within {STEP_TIMEOUT}s")
            print("\nStopping test because target PPS could not be reached and held in time.")
            break

        # Cool-down between steps so the window resets cleanly
        time.sleep(5)

    # Restore a sane threshold
    set_threshold(10)

    # Print summary table
    print("\n" + "=" * 42)
    print(f"{'Target PPS':>12}  {'Avg PI Rate':>12}  {'Peak PI Rate':>13}")
    print("-" * 42)
    for r in rows:
        print(f"{r['target_pps']:>12}  {r['avg_pi_rate']:>12}  {r['peak_pi_rate']:>13}")
    print("=" * 42)

    # Write CSV
    try:
        with open(OUTPUT_CSV, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "target_pps",
                    "required_pi_rate",
                    "avg_pi_rate",
                    "peak_pi_rate",
                    "reached_and_held",
                    "time_to_reach_s",
                    "hold_time_s",
                ]
            )
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nResults saved to {OUTPUT_CSV}")
    except OSError as e:
        print(f"WARNING: Could not write CSV: {e}")

    # Find where the rate plateaus (controller can't keep up)
    prev_rate = 0
    for r in rows:
        gain = r["avg_pi_rate"] - prev_rate
        if prev_rate > 0 and gain < prev_rate * 0.1:
            print(f"\nRate appears to plateau around {r['target_pps']} pps "
                  f"(pi_rate gain dropped to {gain:.1f}/s).")
            break
        prev_rate = r["avg_pi_rate"]


if __name__ == "__main__":
    main()
