#!/usr/bin/env python3
"""
Unprotected saturation test for the Self-Healing SDN Controller.

Modes:
1) Stepped mode (default): no args needed. Walks a PPS ladder and looks
    for saturation/plateau behavior.
2) Fixed-rate mode (--pps N): sends traffic at N pps for 90 seconds and
    reports aggregate stats.
3) Granularity mode (--granularity): wait for trust_test.py start signal,
    then run fixed-rate saturation.
"""

import argparse
import os
import random
import socket
import sys
import time
import threading

from scapy.all import Ether, IP, UDP, Raw, sendp, conf

try:
    from test_suite.test_common import (
        get_stats as common_get_stats,
        parse_cpu_percent as common_parse_cpu_percent,
        reset_controller as common_reset_controller,
        set_mitigation_enabled as common_set_mitigation_enabled,
    )
except ModuleNotFoundError:
    from test_common import (
        get_stats as common_get_stats,
        parse_cpu_percent as common_parse_cpu_percent,
        reset_controller as common_reset_controller,
        set_mitigation_enabled as common_set_mitigation_enabled,
    )

# ---------------------------------------------------------------------------
# Configuration — edit these to match your setup
# ---------------------------------------------------------------------------
IFACE          = "eth1"                    # data-plane interface facing OVS
CONTROLLER_API = "http://128.110.223.3:8080"  # Ryu REST API

# Default stepped-mode ladder.
RAMP_STEPS     = [50, 100, 250, 500, 1000, 2000, 5000, 10000]
STEP_DURATION  = 10   # seconds rate must stay at target once reached
STEP_TIMEOUT   = 60   # abort current/overall test if target not reached in this time
RATE_TOLERANCE = 0.95 # consider target reached at >= target_pps * RATE_TOLERANCE
POLL_INTERVAL  = 2    # seconds between REST polls within a step
FLOOD_BURST_SIZE = 256 # packets per send call; larger bursts reduce Python overhead
CPU_STAT_KEY   = "controller_cpu_percent"
REQUIRE_CPU_METRICS = True
FIXED_MODE_SECONDS = 90
DEFAULT_UNIQUE_SOURCES = False
GRANULARITY_HOST = "0.0.0.0"
GRANULARITY_PORT = 9010
GRANULARITY_TOKEN = "START"
GRANULARITY_WAIT_TIMEOUT = 180

# Destination — unknown dst MAC forces every packet to hit the controller
DST_MAC = "ff:ff:ff:ff:ff:ff"
DST_IP  = "10.0.0.1"
TARGET_PACKET_BYTES = 256
PAD_BYTE = b"X"
# ---------------------------------------------------------------------------


def get_stats():
    return common_get_stats(CONTROLLER_API)


def parse_cpu_percent(stats):
    return common_parse_cpu_percent(stats, CPU_STAT_KEY)


def set_mitigation_enabled(enabled):
    return common_set_mitigation_enabled(CONTROLLER_API, enabled)


def reset_controller():
    return common_reset_controller(CONTROLLER_API)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run unprotected saturation test for the Self-Healing SDN Controller."
    )
    parser.add_argument(
        "--pps",
        type=int,
        default=0,
        help="Fixed-rate mode: send this PPS for 90 seconds (example: --pps 1300)",
    )
    parser.add_argument(
        "--granularity",
        action="store_true",
        help="Wait for trust_test.py handshake before starting saturation",
    )
    parser.add_argument(
        "--unique-sources",
        action="store_true",
        default=DEFAULT_UNIQUE_SOURCES,
        help="Generate random source MAC/IP per packet (higher CPU cost on sender)",
    )
    parser.add_argument("--skip-reset-controller", action="store_true")
    return parser.parse_args()


def wait_for_granularity_start(host, port, token, timeout_sec):
    """Block until a matching START token is received over TCP."""
    deadline = time.time() + timeout_sec
    print(f"Granularity wait: listen={host}:{port} token='{token}' timeout={timeout_sec}s")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)

        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            server.settimeout(min(1.0, remaining))
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue

            with conn:
                conn.settimeout(2.0)
                try:
                    payload = conn.recv(64).decode("utf-8", errors="ignore").strip()
                except OSError:
                    payload = ""

                if payload == token:
                    try:
                        conn.sendall(b"ACK\n")
                    except OSError:
                        pass
                    print(f"Granularity signal accepted from {addr[0]}:{addr[1]}")
                    return True

                print(f"Granularity signal ignored from {addr[0]}:{addr[1]}: token='{payload}'")

    return False


def make_packet(unique_sources=False):
    """Build one attack packet. Randomized sources are optional for generator performance."""
    if unique_sources:
        src_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(
            random.randint(0, 255) for _ in range(5)
        )
        src_ip = "10.%d.%d.%d" % (
            random.randint(1, 254),
            random.randint(1, 254),
            random.randint(1, 254),
        )
    else:
        src_mac = "02:00:00:00:00:01"
        src_ip = "10.1.0.1"

    base = (
        Ether(src=src_mac, dst=DST_MAC) /
        IP(src=src_ip, dst=DST_IP, ttl=64) /
        UDP(sport=random.randint(1024, 65535), dport=9999)
    )
    payload_len = max(0, TARGET_PACKET_BYTES - len(base))
    return base / Raw(load=PAD_BYTE * payload_len)


def flood(target_pps, stop_event, unique_sources=False):
    """Continuously send packets as close to target_pps as possible."""
    burst_size = max(1, FLOOD_BURST_SIZE)
    burst_interval = burst_size / float(target_pps)
    sent = 0
    next_send = time.perf_counter()

    prebuilt_burst = None
    if not unique_sources:
        prebuilt_burst = [make_packet(unique_sources=False) for _ in range(burst_size)]

    while not stop_event.is_set():
        if unique_sources:
            packets = [make_packet(unique_sources=True) for _ in range(burst_size)]
        else:
            packets = prebuilt_burst
        sendp(packets, iface=IFACE, verbose=False)
        sent += burst_size

        next_send += burst_interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            # If we fall behind at high PPS, resync to avoid runaway drift.
            next_send = time.perf_counter()

    return sent


def run_step(target_pps, unique_sources=False):
    """
    Flood at target_pps until measured rate reaches the tolerated target and
    remains there for STEP_DURATION seconds, or until STEP_TIMEOUT is exceeded.
    Returns (avg_pi_rate, peak_pi_rate, avg_cpu, peak_cpu,
             reached_target, time_to_reach, hold_time, required_rate).
    """
    stop_event = threading.Event()
    flood_thread = threading.Thread(
        target=flood, args=(target_pps, stop_event, unique_sources), daemon=True
    )
    flood_thread.start()

    rates = []
    cpu_rates = []
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
            cpu = parse_cpu_percent(stats)
            rates.append(rate)
            mitigation_on = stats.get("mitigation_active")
            mit_tag = "  [MITIGATION ACTIVE]" if mitigation_on else ""
            if cpu is not None:
                cpu_rates.append(cpu)
                print(f"    target={target_pps} pps  measured pi_rate={rate}/s  cpu={cpu}%{mit_tag}")
            else:
                print(f"    target={target_pps} pps  measured pi_rate={rate}/s{mit_tag}")

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
    avg_cpu = round(sum(cpu_rates) / len(cpu_rates), 2) if cpu_rates else None
    peak_cpu = round(max(cpu_rates), 2) if cpu_rates else None
    return avg, peak, avg_cpu, peak_cpu, reached_target and hold_time >= STEP_DURATION, round(time_to_reach, 2) if time_to_reach is not None else None, round(hold_time, 2), round(required_rate, 2)


def run_fixed_rate(pps, run_seconds=FIXED_MODE_SECONDS, unique_sources=False):
    """Run a fixed-rate flood and return aggregate stats for the window."""
    stop_event = threading.Event()
    flood_thread = threading.Thread(
        target=flood,
        args=(pps, stop_event, unique_sources),
        daemon=True,
    )
    flood_thread.start()

    rates = []
    cpu_rates = []
    start = time.time()

    while time.time() - start < run_seconds:
        stats = get_stats()
        if stats:
            rate = stats.get("packet_in_rate", 0)
            cpu = parse_cpu_percent(stats)
            rates.append(rate)
            if cpu is not None:
                cpu_rates.append(cpu)
                print(f"    fixed={pps} pps  measured pi_rate={rate}/s  cpu={cpu}%")
            else:
                print(f"    fixed={pps} pps  measured pi_rate={rate}/s")
        time.sleep(POLL_INTERVAL)

    stop_event.set()
    flood_thread.join(timeout=3)

    avg = round(sum(rates) / len(rates), 2) if rates else 0
    peak = round(max(rates), 2) if rates else 0
    avg_cpu = round(sum(cpu_rates) / len(cpu_rates), 2) if cpu_rates else None
    peak_cpu = round(max(cpu_rates), 2) if cpu_rates else None
    return avg, peak, avg_cpu, peak_cpu


def prepare_controller(skip_reset_controller):
    """Shared pre-flight: connectivity check, disable mitigation, optional reset."""
    stats = get_stats()
    if stats is None:
        print("ERROR: Cannot reach Ryu REST API. Is the controller running?")
        sys.exit(1)

    initial_cpu = parse_cpu_percent(stats)
    if REQUIRE_CPU_METRICS and initial_cpu is None:
        keys = ", ".join(sorted(stats.keys())) if isinstance(stats, dict) else "<non-dict response>"
        print(f"ERROR: /stats is missing a numeric '{CPU_STAT_KEY}' value.")
        print(f"       Returned keys: {keys}")
        print("       Restart the controller process that serves this API and rerun the test.")
        sys.exit(2)

    print(f"Controller reachable — uptime={stats.get('uptime_seconds')}s")
    print()

    if not set_mitigation_enabled(False):
        print("ERROR: Could not disable mitigation — aborting to avoid protection bias.")
        sys.exit(3)
    if not skip_reset_controller:
        if not reset_controller():
            print("ERROR: Could not reset controller state — aborting.")
            sys.exit(4)
    else:
        print("WARNING: Skipping controller reset; prior controller state is preserved.")

    verify = get_stats()
    mitigation_enabled = verify.get("mitigation_enabled") if verify else None
    if mitigation_enabled is not False:
        print(f"ERROR: Controller mitigation_enabled is {mitigation_enabled!r}, expected False.")
        print("       Restart the controller and rerun the test.")
        sys.exit(5)
    time.sleep(1)


def main():
    args = parse_args()

    if args.pps < 0:
        print("ERROR: --pps must be >= 0.")
        sys.exit(2)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ERROR: Scapy sendp() requires raw-socket privileges.")
        print("       Run with: sudo python3.8 ./test_suite/unprotected_saturation_test.py")
        sys.exit(1)

    conf.iface = IFACE

    print(f"Interface      : {IFACE}")
    print(f"Controller API : {CONTROLLER_API}")
    print(f"Unique sources : {args.unique_sources}")
    prepare_controller(args.skip_reset_controller)

    if args.granularity:
        if args.pps <= 0:
            print("ERROR: --granularity requires fixed-rate mode: provide --pps N")
            sys.exit(2)
        started = wait_for_granularity_start(
            GRANULARITY_HOST,
            GRANULARITY_PORT,
            GRANULARITY_TOKEN,
            GRANULARITY_WAIT_TIMEOUT,
        )
        if not started:
            print("ERROR: Timed out waiting for granularity start signal.")
            sys.exit(6)
        print()

    # Fixed-rate mode: --pps N
    if args.pps > 0:
        print(f"Mode          : FIXED")
        print(f"Requested PPS : {args.pps}")
        print(f"Duration      : {FIXED_MODE_SECONDS}s")
        print()

        avg_rate, peak_rate, avg_cpu, peak_cpu = run_fixed_rate(
            args.pps,
            FIXED_MODE_SECONDS,
            unique_sources=args.unique_sources,
        )
        avg_cpu_str = f"{avg_cpu}%" if avg_cpu is not None else "n/a"
        peak_cpu_str = f"{peak_cpu}%" if peak_cpu is not None else "n/a"

        print("\n" + "=" * 60)
        print("Fixed-Rate Saturation Summary")
        print("-" * 60)
        print(f"Requested PPS : {args.pps}")
        print(f"Avg PI/s      : {avg_rate}")
        print(f"Peak PI/s     : {peak_rate}")
        print(f"Avg CPU%      : {avg_cpu_str}")
        print(f"Peak CPU%     : {peak_cpu_str}")
        print("=" * 60)

        set_mitigation_enabled(True)
        return

    # Default stepped mode
    print("Mode          : STEPPED")
    print(f"Ramp steps    : {RAMP_STEPS} pps")
    print(f"Rate tolerance: {int(RATE_TOLERANCE * 100)}% of target")
    print(f"Hold duration : {STEP_DURATION}s at target")
    print(f"Step timeout  : {STEP_TIMEOUT}s max to reach/hold target")
    print()

    rows = []
    top_hdr = f"{'Target PPS':>12}  {'Avg PI Rate':>12}  {'Avg CPU %':>10}"
    top_sep = "-" * len(top_hdr)
    print(top_hdr)
    print(top_sep)

    for target_pps in RAMP_STEPS:
        print(f"\n  Step: {target_pps} pps (must hold >= target for {STEP_DURATION}s) ...")
        avg_rate, peak_rate, avg_cpu, peak_cpu, reached_hold, time_to_reach, hold_time, required_rate = run_step(
            target_pps,
            unique_sources=args.unique_sources,
        )

        rows.append({
            "target_pps":   target_pps,
            "required_pi_rate": required_rate,
            "avg_pi_rate":  avg_rate,
            "peak_pi_rate": peak_rate,
            "avg_cpu_percent": avg_cpu,
            "peak_cpu_percent": peak_cpu,
            "reached_and_held": reached_hold,
            "time_to_reach_s": time_to_reach,
            "hold_time_s": hold_time,
        })
        avg_cpu_str = f"{avg_cpu}%" if avg_cpu is not None else "n/a"
        peak_cpu_str = f"{peak_cpu}%" if peak_cpu is not None else "n/a"
        if reached_hold:
            print(f"  -> avg={avg_rate}/s  peak={peak_rate}/s  avg_cpu={avg_cpu_str}  peak_cpu={peak_cpu_str}  reached_in={time_to_reach}s  required>={required_rate}/s")
        else:
            print(f"  -> avg={avg_rate}/s  peak={peak_rate}/s  avg_cpu={avg_cpu_str}  peak_cpu={peak_cpu_str}  FAILED to hold >= {required_rate}/s within {STEP_TIMEOUT}s")
            print("\nStopping test because target PPS could not be reached and held in time.")
            break

        # Cool-down between steps so the window resets cleanly
        time.sleep(5)

    # Restore mitigation for normal controller operation.
    set_mitigation_enabled(True)

    # Print summary table
    summary_hdr = f"{'Target PPS':>12}  {'Avg PI Rate':>12}  {'Peak PI Rate':>13}  {'Avg CPU %':>10}  {'Peak CPU %':>11}"
    summary_sep = "-" * len(summary_hdr)
    print("\n" + "=" * len(summary_hdr))
    print(summary_hdr)
    print(summary_sep)
    for r in rows:
        avg_cpu = r['avg_cpu_percent'] if r['avg_cpu_percent'] is not None else "n/a"
        peak_cpu = r['peak_cpu_percent'] if r['peak_cpu_percent'] is not None else "n/a"
        print(f"{r['target_pps']:>12}  {r['avg_pi_rate']:>12}  {r['peak_pi_rate']:>13}  {avg_cpu:>10}  {peak_cpu:>11}")
    print("=" * len(summary_hdr))

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
