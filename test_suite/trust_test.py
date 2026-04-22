#!/usr/bin/env python3
"""
Trust test focused on two workflows:
1) --compromised N
   Send benign packets until the source is trusted, then switch to 256-byte
   packets at N pps.
2) --granularity
   Same trust-build phase, then signal a saturation node and keep sending
   256-byte traffic while saturation runs.

All output is stdout-only with [METRIC] and [SAMPLE] tags for audit logs.
"""

import argparse
import os
import random
import socket
import sys
import threading
import time

import requests
from scapy.all import Ether, IP, UDP, Raw, conf, sendp

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
DEFAULT_SOURCE_MAC = "02:00:00:00:00:01"
DEFAULT_SOURCE_IP = "10.1.0.1"
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_RUN_SECONDS = 30
DEFAULT_BENIGN_PPS = 10
DEFAULT_TRUST_TIMEOUT_SEC = 60
DEFAULT_THRESHOLD_MARGIN = 50
ATTACK_PACKET_BYTES = 256
BENIGN_PACKET_BYTES = 64


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


def clear_trust_state(controller_api):
    try:
        response = requests.post(controller_api + "/trust/clear", timeout=4)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        print(f"[REST] /trust/clear failed: {exc}")
        return None


def wait_for_trust(controller_api, source_mac, timeout_sec):
    try:
        url = f"{controller_api}/trust/watch?source_mac={source_mac}&timeout_sec={timeout_sec}"
        response = requests.post(url, timeout=timeout_sec + 5)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        print(f"[REST] /trust/watch failed: {exc}")
        return None


def make_packet(src_mac, src_ip, dst_mac, dst_ip, packet_bytes):
    base = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / UDP(sport=random.randint(1024, 65535), dport=9999)
    )
    payload_len = max(0, packet_bytes - len(base))
    if payload_len > 0:
        return base / Raw(load=b"X" * payload_len)
    return base


def send_source_traffic(args, stop_event, pps, packet_bytes):
    rate = max(1, int(pps))
    interval = 1.0 / float(rate)
    next_send = time.perf_counter()

    while not stop_event.is_set():
        pkt = make_packet(
            args.source_mac,
            args.source_ip,
            args.dst_mac,
            args.dst_ip,
            packet_bytes,
        )
        sendp(pkt, iface=args.iface, verbose=False)

        next_send += interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            next_send = time.perf_counter()


def collect_sample(args):
    stats = get_stats(args.controller_api) or {}
    metrics = get_attack_metrics(args.controller_api) or {}
    mitigation = metrics.get("mitigation", {})
    trusted_sources = mitigation.get("trusted_sources", [])
    source_counts = mitigation.get("source_packet_counts", {})

    raw_count = source_counts.get(args.source_mac, 0)
    try:
        source_count = int(raw_count)
    except (TypeError, ValueError):
        source_count = 0

    return {
        "ts": time.time(),
        "pi_rate": stats.get("packet_in_rate", 0),
        "cpu": parse_cpu_percent(stats, args.cpu_key),
        "attack_detected": bool(stats.get("attack_detected", False)),
        "source_trusted": args.source_mac in trusted_sources,
        "source_count": source_count,
    }


def summarize_samples(samples):
    if not samples:
        print("[METRIC] sample_count=0")
        return

    pi_values = [float(s["pi_rate"]) for s in samples if isinstance(s["pi_rate"], (int, float))]
    cpu_values = [float(s["cpu"]) for s in samples if isinstance(s["cpu"], (int, float))]
    attack_count = sum(1 for s in samples if s["attack_detected"])

    avg_pi = round(sum(pi_values) / len(pi_values), 2) if pi_values else 0
    peak_pi = round(max(pi_values), 2) if pi_values else 0
    avg_cpu = round(sum(cpu_values) / len(cpu_values), 2) if cpu_values else None
    peak_cpu = round(max(cpu_values), 2) if cpu_values else None
    attack_ratio = round((attack_count / len(samples)) * 100.0, 2)

    print(f"[METRIC] sample_count={len(samples)}")
    print(f"[METRIC] avg_pi_rate={avg_pi}")
    print(f"[METRIC] peak_pi_rate={peak_pi}")
    print(f"[METRIC] avg_cpu={avg_cpu if avg_cpu is not None else 'n/a'}")
    print(f"[METRIC] peak_cpu={peak_cpu if peak_cpu is not None else 'n/a'}")
    print(f"[METRIC] attack_detected_ratio_pct={attack_ratio}")


def run_test_window(args, attack_pps):
    stop_event = threading.Event()
    sender = threading.Thread(
        target=send_source_traffic,
        args=(args, stop_event, attack_pps, ATTACK_PACKET_BYTES),
        daemon=True,
    )
    sender.start()

    samples = []
    start = time.time()
    while time.time() - start < args.run_seconds:
        sample = collect_sample(args)
        samples.append(sample)
        cpu_str = f"{round(sample['cpu'], 2)}" if sample["cpu"] is not None else "n/a"
        print(
            f"[SAMPLE] t={round(sample['ts'] - start, 2)} pi={sample['pi_rate']} "
            f"cpu={cpu_str} attack={sample['attack_detected']} "
            f"trusted={sample['source_trusted']} src_cnt={sample['source_count']}"
        )
        time.sleep(args.poll_interval)

    stop_event.set()
    sender.join(timeout=3)
    summarize_samples(samples)


def run_compromised_mode(args, threshold):
    attack_pps = args.compromised if args.compromised > 0 else threshold + max(1, args.threshold_margin)
    if attack_pps <= threshold:
        attack_pps = threshold + 1

    print("[METRIC] mode=compromised")
    print(f"[METRIC] source_mac={args.source_mac}")
    print(f"[METRIC] benign_pps={args.benign_pps}")
    print(f"[METRIC] attack_pps={attack_pps}")

    if args.clear_trust:
        print(f"[METRIC] trust_clear_status={'ok' if clear_trust_state(args.controller_api) else 'failed'}")

    benign_stop = threading.Event()
    benign_sender = threading.Thread(
        target=send_source_traffic,
        args=(args, benign_stop, args.benign_pps, BENIGN_PACKET_BYTES),
        daemon=True,
    )
    benign_sender.start()

    print("[PHASE] benign_wait_for_trust")
    trust_result = wait_for_trust(args.controller_api, args.source_mac, args.trust_timeout_sec)
    benign_stop.set()
    benign_sender.join(timeout=3)

    if trust_result is None or trust_result.get("status") != "trusted":
        print(f"[METRIC] trust_status={trust_result.get('status') if trust_result else 'error'}")
        print("[ERROR] source was not trusted before timeout")
        return

    print("[METRIC] trust_status=trusted")
    print(f"[METRIC] time_to_trust_sec={trust_result.get('time_to_trust', 0)}")
    print("[PHASE] compromised_attack")
    run_test_window(args, attack_pps)


def run_granularity_mode(args, threshold):
    if not args.saturation_node:
        print("[ERROR] --saturation-node host:port is required for --granularity")
        return

    granularity_pps = args.compromised if args.compromised > 0 else max(100, threshold // 8)
    print("[METRIC] mode=granularity")
    print(f"[METRIC] source_mac={args.source_mac}")
    print(f"[METRIC] benign_pps={args.benign_pps}")
    print(f"[METRIC] granularity_pps={granularity_pps}")
    print(f"[METRIC] saturation_node={args.saturation_node}")

    if args.clear_trust:
        print(f"[METRIC] trust_clear_status={'ok' if clear_trust_state(args.controller_api) else 'failed'}")

    benign_stop = threading.Event()
    benign_sender = threading.Thread(
        target=send_source_traffic,
        args=(args, benign_stop, args.benign_pps, BENIGN_PACKET_BYTES),
        daemon=True,
    )
    benign_sender.start()

    print("[PHASE] benign_wait_for_trust")
    trust_result = wait_for_trust(args.controller_api, args.source_mac, args.trust_timeout_sec)
    benign_stop.set()
    benign_sender.join(timeout=3)

    if trust_result is None or trust_result.get("status") != "trusted":
        print(f"[METRIC] trust_status={trust_result.get('status') if trust_result else 'error'}")
        print("[ERROR] source was not trusted before timeout")
        return

    print("[METRIC] trust_status=trusted")
    print(f"[METRIC] time_to_trust_sec={trust_result.get('time_to_trust', 0)}")

    try:
        host, port_str = args.saturation_node.split(":", 1)
        port = int(port_str)
    except ValueError:
        print("[ERROR] --saturation-node must be in host:port format")
        return

    print("[PHASE] signal_saturation_node")
    try:
        payload = (args.signal_token + "\n").encode("utf-8")
        with socket.create_connection((host, port), timeout=args.signal_timeout) as sock:
            sock.sendall(payload)
            sock.settimeout(args.signal_timeout)
            try:
                sock.recv(64)
            except (socket.timeout, OSError):
                pass
        print("[METRIC] saturation_signal=sent")
    except OSError as exc:
        print("[METRIC] saturation_signal=failed")
        print(f"[ERROR] saturation handshake failed: {exc}")
        return

    print("[PHASE] granularity_attack_under_saturation")
    run_test_window(args, granularity_pps)


def parse_args():
    parser = argparse.ArgumentParser(description="Trust test (compromised/granularity modes)")
    parser.add_argument("--compromised", type=int, default=0, help="Attack pps after trust is established")
    parser.add_argument("--granularity", action="store_true", help="Enable granularity mode (requires --saturation-node)")
    parser.add_argument("--saturation-node", default="", help="Target saturation listener in host:port format")
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--controller-api", default=DEFAULT_CONTROLLER_API)
    parser.add_argument("--cpu-key", default=DEFAULT_CPU_KEY)
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC)
    parser.add_argument("--dst-ip", default=DEFAULT_DST_IP)
    parser.add_argument("--source-mac", default=DEFAULT_SOURCE_MAC)
    parser.add_argument("--source-ip", default=DEFAULT_SOURCE_IP)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--run-seconds", type=int, default=DEFAULT_RUN_SECONDS)
    parser.add_argument("--benign-pps", type=int, default=DEFAULT_BENIGN_PPS)
    parser.add_argument("--trust-timeout-sec", type=int, default=DEFAULT_TRUST_TIMEOUT_SEC)
    parser.add_argument("--threshold-margin", type=int, default=DEFAULT_THRESHOLD_MARGIN)
    parser.add_argument("--signal-token", default="START")
    parser.add_argument("--signal-timeout", type=float, default=5.0)
    parser.add_argument("--clear-trust", action="store_true")
    parser.add_argument("--reset-controller", action="store_true")
    parser.add_argument("--disable-mitigation", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.poll_interval <= 0 or args.run_seconds <= 0 or args.benign_pps <= 0 or args.trust_timeout_sec <= 0:
        print("ERROR: poll/run/benign/trust timeout values must be > 0")
        sys.exit(1)

    if args.signal_timeout <= 0:
        print("ERROR: --signal-timeout must be > 0")
        sys.exit(1)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ERROR: Scapy sendp() requires raw-socket privileges.")
        print("       Run with: sudo python3 ./test_suite/trust_test.py ...")
        sys.exit(1)

    conf.iface = args.iface

    stats = get_stats(args.controller_api)
    if stats is None:
        print("ERROR: cannot reach controller REST API")
        sys.exit(2)

    threshold = int(stats.get("packet_in_threshold", 800))
    print(f"[METRIC] threshold={threshold}")

    if args.reset_controller and not reset_controller(args.controller_api):
        print("ERROR: could not reset controller state")
        sys.exit(3)

    if args.disable_mitigation and not set_mitigation_enabled(args.controller_api, False):
        print("ERROR: could not disable mitigation")
        sys.exit(4)

    if args.granularity:
        run_granularity_mode(args, threshold)
    else:
        run_compromised_mode(args, threshold)


if __name__ == "__main__":
    main()
