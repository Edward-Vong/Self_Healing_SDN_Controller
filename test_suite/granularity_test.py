#!/usr/bin/env python3
"""
Granularity/compromised-source tester for the Self-Healing SDN Controller.

This script can run in two ways:
1) Standalone: generate trusted traffic, optionally compromise the trusted source,
   and optionally add local saturation traffic.
2) Companion: run only trusted/compromised source behavior while a separate
   saturation script runs on another node.
"""

import argparse
import os
import random
import socket
import sys
import threading
import time

from scapy.all import Ether, IP, UDP, conf, sendp

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


DEFAULT_IFACE = "eth1"
DEFAULT_CONTROLLER_API = "http://128.110.223.3:8080"
DEFAULT_CPU_KEY = "controller_cpu_percent"
DEFAULT_DST_MAC = "ff:ff:ff:ff:ff:ff"
DEFAULT_DST_IP = "10.0.0.1"
DEFAULT_RUN_SECONDS = 90
DEFAULT_COMPROMISE_AT = 30
DEFAULT_LEGIT_PPS = 50
DEFAULT_LOCAL_SATURATION_PPS = 1300
DEFAULT_TRUST_SEED_PACKETS = 10
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_SOURCE_MAC = "02:00:00:00:00:01"
DEFAULT_SOURCE_IP = "10.1.0.1"
DEFAULT_THRESHOLD_MARGIN = 50
LOCAL_FLOOD_BURST_SIZE = 256


def get_stats(controller_api):
    return common_get_stats(controller_api)


def get_attack_metrics(controller_api):
    return common_get_attack_metrics(controller_api)


def parse_cpu_percent(stats, cpu_key):
    return common_parse_cpu_percent(stats, cpu_key)


def reset_controller(controller_api):
    return common_reset_controller(controller_api)


def set_mitigation_enabled(controller_api, enabled):
    return common_set_mitigation_enabled(controller_api, enabled)


def make_packet(src_mac, src_ip, dst_mac, dst_ip):
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / UDP(sport=random.randint(1024, 65535), dport=9999)
    )


def make_random_packet(dst_mac, dst_ip):
    src_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5)
    )
    src_ip = "10.%d.%d.%d" % (
        random.randint(1, 254),
        random.randint(1, 254),
        random.randint(1, 254),
    )
    return make_packet(src_mac, src_ip, dst_mac, dst_ip)


def seed_trust(args):
    print(
        f"Seeding trust for {args.source_mac} with "
        f"{args.trust_seed_packets} packets..."
    )
    packets = [
        make_packet(args.source_mac, args.source_ip, args.dst_mac, args.dst_ip)
        for _ in range(args.trust_seed_packets)
    ]
    sendp(packets, iface=args.iface, verbose=False)


def trusted_source_sender(args, rate_state, stop_event):
    next_send = time.perf_counter()

    while not stop_event.is_set():
        with rate_state["lock"]:
            pps = rate_state["pps"]

        if pps <= 0:
            time.sleep(0.05)
            continue

        pkt = make_packet(args.source_mac, args.source_ip, args.dst_mac, args.dst_ip)
        sendp(pkt, iface=args.iface, verbose=False)

        interval = 1.0 / float(pps)
        next_send += interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            next_send = time.perf_counter()


def local_saturation_sender(args, stop_event):
    target_pps = max(1, args.local_saturation_pps)
    burst_size = max(1, LOCAL_FLOOD_BURST_SIZE)
    burst_interval = burst_size / float(target_pps)
    next_send = time.perf_counter()

    while not stop_event.is_set():
        packets = [make_random_packet(args.dst_mac, args.dst_ip) for _ in range(burst_size)]
        sendp(packets, iface=args.iface, verbose=False)

        next_send += burst_interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            next_send = time.perf_counter()


def send_start_signal(args):
    if not args.signal_saturation_host:
        return True

    payload = (args.signal_token + "\n").encode("utf-8")
    for attempt in range(1, args.signal_retries + 1):
        try:
            with socket.create_connection(
                (args.signal_saturation_host, args.signal_saturation_port),
                timeout=args.signal_timeout,
            ) as sock:
                sock.sendall(payload)
                sock.settimeout(args.signal_timeout)
                try:
                    sock.recv(64)
                except socket.timeout:
                    pass
                except OSError:
                    pass
                print(
                    "Sent saturation start signal to "
                    f"{args.signal_saturation_host}:{args.signal_saturation_port}"
                )
                return True
        except OSError as exc:
            print(
                f"Start-signal attempt {attempt}/{args.signal_retries} failed "
                f"to {args.signal_saturation_host}:{args.signal_saturation_port}: {exc}"
            )
            if attempt < args.signal_retries:
                time.sleep(args.signal_retry_interval)

    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="Granularity tester with protected/unprotected and compromised scenarios"
    )
    parser.add_argument(
        "--mode",
        choices=["unprotected", "protected"],
        default="unprotected",
        help="Expected controller mitigation mode",
    )
    parser.add_argument(
        "--scenario",
        choices=["trust_only", "compromised_only", "compromised_with_saturation"],
        default="compromised_only",
        help="Test scenario",
    )
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--controller-api", default=DEFAULT_CONTROLLER_API)
    parser.add_argument("--cpu-key", default=DEFAULT_CPU_KEY)
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC)
    parser.add_argument("--dst-ip", default=DEFAULT_DST_IP)
    parser.add_argument("--source-mac", default=DEFAULT_SOURCE_MAC)
    parser.add_argument("--source-ip", default=DEFAULT_SOURCE_IP)
    parser.add_argument("--run-seconds", type=int, default=DEFAULT_RUN_SECONDS)
    parser.add_argument("--compromise-at-sec", type=int, default=DEFAULT_COMPROMISE_AT)
    parser.add_argument("--legit-pps", type=int, default=DEFAULT_LEGIT_PPS)
    parser.add_argument("--compromised-pps", type=int, default=0)
    parser.add_argument("--threshold-margin", type=int, default=DEFAULT_THRESHOLD_MARGIN)
    parser.add_argument("--trust-seed-packets", type=int, default=DEFAULT_TRUST_SEED_PACKETS)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--local-saturation-pps", type=int, default=DEFAULT_LOCAL_SATURATION_PPS)
    parser.add_argument("--signal-saturation-host", default="")
    parser.add_argument("--signal-saturation-port", type=int, default=9010)
    parser.add_argument("--signal-token", default="START")
    parser.add_argument("--signal-timeout", type=float, default=5.0)
    parser.add_argument("--signal-retries", type=int, default=30)
    parser.add_argument("--signal-retry-interval", type=float, default=1.0)
    parser.add_argument(
        "--manage-mitigation",
        action="store_true",
        help="Set mitigation mode via REST before test (useful for standalone runs)",
    )
    parser.add_argument(
        "--reset-controller",
        action="store_true",
        help="Reset controller before trust seeding (useful for clean standalone runs)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.signal_saturation_port < 1 or args.signal_saturation_port > 65535:
        print("ERROR: --signal-saturation-port must be in range 1..65535.")
        sys.exit(1)
    if args.signal_timeout <= 0:
        print("ERROR: --signal-timeout must be > 0.")
        sys.exit(1)
    if args.signal_retries <= 0:
        print("ERROR: --signal-retries must be > 0.")
        sys.exit(1)
    if args.signal_retry_interval <= 0:
        print("ERROR: --signal-retry-interval must be > 0.")
        sys.exit(1)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ERROR: Scapy sendp() requires raw-socket privileges.")
        print("       Run with: sudo python3.8 ./test_suite/granularity_test.py ...")
        sys.exit(1)

    conf.iface = args.iface

    stats = get_stats(args.controller_api)
    if stats is None:
        print("ERROR: Cannot reach controller REST API.")
        sys.exit(2)

    threshold = int(stats.get("packet_in_threshold", 800))
    compromised_pps = args.compromised_pps
    if compromised_pps <= 0:
        compromised_pps = threshold + max(1, args.threshold_margin)

    if compromised_pps <= threshold:
        print(
            f"WARNING: compromised_pps={compromised_pps} is not above threshold={threshold}. "
            f"Adjusting to {threshold + 1}."
        )
        compromised_pps = threshold + 1

    if args.manage_mitigation:
        desired_enabled = args.mode == "protected"
        if not set_mitigation_enabled(args.controller_api, desired_enabled):
            print("ERROR: Could not set mitigation mode via REST.")
            sys.exit(3)

    if args.reset_controller:
        if not reset_controller(args.controller_api):
            print("ERROR: Could not reset controller state.")
            sys.exit(4)
        time.sleep(1)

    print(f"Mode               : {args.mode}")
    print(f"Scenario           : {args.scenario}")
    print(f"Interface          : {args.iface}")
    print(f"Controller API     : {args.controller_api}")
    print(f"Trusted source     : {args.source_mac} ({args.source_ip})")
    print(f"Legitimate PPS     : {args.legit_pps}")
    print(f"Compromise time    : {args.compromise_at_sec}s")
    print(f"Compromised PPS    : {compromised_pps} (threshold={threshold})")
    if args.scenario == "compromised_with_saturation":
        print(f"Local saturation   : ON ({args.local_saturation_pps} pps)")
    else:
        print("Local saturation   : OFF (can run alongside external saturation test)")
    if args.signal_saturation_host:
        print(
            "Saturation signal  : ON "
            f"({args.signal_saturation_host}:{args.signal_saturation_port})"
        )
    print()

    seed_trust(args)
    time.sleep(2)

    initial_metrics = get_attack_metrics(args.controller_api) or {}
    mitigation = initial_metrics.get("mitigation", {})
    trusted_list = mitigation.get("trusted_sources", [])
    print(
        "TRUST SEEDED: "
        f"trusted_count={len(trusted_list)} "
        f"source_trusted={'YES' if args.source_mac in trusted_list else 'NO'}"
    )
    print()

    stop_event = threading.Event()
    rate_state = {"pps": args.legit_pps, "lock": threading.Lock()}

    sender_thread = threading.Thread(
        target=trusted_source_sender,
        args=(args, rate_state, stop_event),
        daemon=True,
    )
    sender_thread.start()

    if not send_start_signal(args):
        print("ERROR: Failed to send saturation start signal after all retries.")
        stop_event.set()
        sender_thread.join(timeout=3)
        sys.exit(5)

    saturation_thread = None
    if args.scenario == "compromised_with_saturation":
        saturation_thread = threading.Thread(
            target=local_saturation_sender,
            args=(args, stop_event),
            daemon=True,
        )
        saturation_thread.start()

    compromised = False
    trust_revoked_at = None
    was_ever_trusted = args.source_mac in trusted_list
    previous_source_count = None

    samples = []
    test_start = time.time()

    header = (
        f"{'t(s)':>6}  {'PI/s':>8}  {'CPU%':>8}  {'Attack':>8}  "
        f"{'MitEn':>6}  {'Trusted?':>8}  {'TrustedN':>8}  {'SrcCnt':>8}  {'dSrc':>6}"
    )
    print(header)
    print("-" * len(header))

    try:
        while True:
            elapsed = time.time() - test_start
            if elapsed >= args.run_seconds:
                break

            if (
                not compromised
                and args.scenario != "trust_only"
                and elapsed >= args.compromise_at_sec
            ):
                with rate_state["lock"]:
                    rate_state["pps"] = compromised_pps
                compromised = True
                print(
                    f"COMPROMISE TRIGGERED at t={round(elapsed, 2)}s: "
                    f"source {args.source_mac} now sending at {compromised_pps} pps"
                )

            stats = get_stats(args.controller_api) or {}
            metrics = get_attack_metrics(args.controller_api) or {}
            mitigation_data = metrics.get("mitigation", {})

            trusted_sources = mitigation_data.get("trusted_sources", [])
            source_counts = mitigation_data.get("source_packet_counts", {})

            source_count_raw = source_counts.get(args.source_mac, 0)
            try:
                source_count = int(source_count_raw)
            except (TypeError, ValueError):
                source_count = 0

            source_delta = 0
            if previous_source_count is not None:
                source_delta = max(0, source_count - previous_source_count)
            previous_source_count = source_count

            source_trusted = args.source_mac in trusted_sources
            was_ever_trusted = was_ever_trusted or source_trusted

            if (
                compromised
                and was_ever_trusted
                and not source_trusted
                and trust_revoked_at is None
            ):
                trust_revoked_at = round(elapsed, 2)
                print(
                    f"TRUST REVOKED at t={trust_revoked_at}s for source {args.source_mac}"
                )

            pi_rate = stats.get("packet_in_rate", 0)
            attack_detected = stats.get("attack_detected", False)
            mitigation_enabled = stats.get("mitigation_enabled", None)
            cpu = parse_cpu_percent(stats, args.cpu_key)
            cpu_str = f"{round(cpu, 2)}" if cpu is not None else "n/a"

            sample = {
                "elapsed": round(elapsed, 2),
                "pi_rate": pi_rate,
                "cpu": cpu,
                "attack_detected": attack_detected,
                "mitigation_enabled": mitigation_enabled,
                "source_trusted": source_trusted,
                "trusted_count": len(trusted_sources),
                "source_count": source_count,
                "source_delta": source_delta,
            }
            samples.append(sample)

            print(
                f"{sample['elapsed']:>6}  {pi_rate:>8}  {cpu_str:>8}  "
                f"{str(attack_detected):>8}  {str(mitigation_enabled):>6}  "
                f"{str(source_trusted):>8}  {len(trusted_sources):>8}  "
                f"{source_count:>8}  {source_delta:>6}"
            )

            time.sleep(args.poll_interval)

    finally:
        stop_event.set()
        sender_thread.join(timeout=3)
        if saturation_thread is not None:
            saturation_thread.join(timeout=3)

    if not samples:
        print("\nNo samples collected.")
        return

    pi_values = [float(s["pi_rate"]) for s in samples if isinstance(s["pi_rate"], (int, float))]
    cpu_values = [float(s["cpu"]) for s in samples if isinstance(s["cpu"], (int, float))]
    trusted_true_count = sum(1 for s in samples if s["source_trusted"])

    avg_pi = round(sum(pi_values) / len(pi_values), 2) if pi_values else 0
    peak_pi = round(max(pi_values), 2) if pi_values else 0
    avg_cpu = round(sum(cpu_values) / len(cpu_values), 2) if cpu_values else None
    peak_cpu = round(max(cpu_values), 2) if cpu_values else None
    trusted_ratio = round((trusted_true_count / len(samples)) * 100.0, 2)

    print("\n" + "=" * 74)
    print("Granularity Summary")
    print("-" * 74)
    print(f"Mode                      : {args.mode}")
    print(f"Scenario                  : {args.scenario}")
    print(f"Avg PI/s                  : {avg_pi}")
    print(f"Peak PI/s                 : {peak_pi}")
    print(f"Avg CPU%                  : {avg_cpu if avg_cpu is not None else 'n/a'}")
    print(f"Peak CPU%                 : {peak_cpu if peak_cpu is not None else 'n/a'}")
    print(f"Source trusted ratio      : {trusted_ratio}% of sampled intervals")
    print(f"Trust revoked timestamp   : {trust_revoked_at if trust_revoked_at is not None else 'not observed'}")
    print("=" * 74)

    if args.mode == "protected" and args.scenario != "trust_only":
        if trust_revoked_at is None:
            print(
                "NOTE: In protected mode, expected trust revocation for over-rate trusted source "
                "was not observed in this run."
            )
    if args.mode == "unprotected" and args.scenario != "trust_only":
        print(
            "NOTE: In unprotected mode, trust may persist because mitigation drop/revocation logic is disabled."
        )


if __name__ == "__main__":
    main()
