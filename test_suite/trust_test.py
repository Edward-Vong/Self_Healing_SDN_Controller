#!/usr/bin/env python3
"""
trust test flow for this project:
1) Send benign traffic from one fixed source until trusted.
2) Optionally signal unprotected_saturation_test.py (--granularity mode).
3) Run hping3 UDP flood while sampling controller metrics.

This script intentionally keeps a minimal argument surface.
"""

import argparse
import os
import random
import socket
import subprocess
import sys
import threading
import time

import requests
from scapy.all import Ether, IP, UDP, Raw, conf, sendp

try:
    from test_suite.test_common import (
        get_attack_metrics as common_get_attack_metrics,
        get_stats as common_get_stats,
        reset_controller as common_reset_controller,
    )
except ModuleNotFoundError:
    from test_common import (
        get_attack_metrics as common_get_attack_metrics,
        get_stats as common_get_stats,
        reset_controller as common_reset_controller,
    )


DEFAULT_IFACE = "eth1"
DEFAULT_CONTROLLER_API = "http://128.110.223.3:8080"
DEFAULT_DST_MAC = "ff:ff:ff:ff:ff:ff"
DEFAULT_DST_IP = "10.0.0.1"
DEFAULT_SOURCE_MAC = "02:00:00:00:00:01"
DEFAULT_SOURCE_IP = "10.1.0.1"
DEFAULT_RUN_SECONDS = 30
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_BENIGN_PPS = 10
DEFAULT_TRUST_TIMEOUT_SEC = 60
DEFAULT_SIGNAL_TIMEOUT = 5.0
DEFAULT_SIGNAL_TOKEN = "START"
BENIGN_PACKET_BYTES = 64
HPING3_BIN = "hping3"
HPING3_ATTACK_DPORT = 9999
HPING3_ATTACK_DLEN = 200


def get_stats(controller_api):
    return common_get_stats(controller_api)


def get_attack_metrics(controller_api):
    return common_get_attack_metrics(controller_api)


def reset_controller(controller_api):
    return common_reset_controller(controller_api)


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


def send_benign_until_stopped(args, stop_event):
    interval = 1.0 / float(max(1, int(args.benign_pps)))
    next_send = time.perf_counter()

    while not stop_event.is_set():
        pkt = make_packet(
            args.source_mac,
            args.source_ip,
            args.dst_mac,
            args.dst_ip,
            BENIGN_PACKET_BYTES,
        )
        sendp(pkt, iface=args.iface, verbose=False)

        next_send += interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
        else:
            next_send = time.perf_counter()


def run_hping3_flood(args, stop_event):
    cmd = [
        HPING3_BIN,
        "--flood",
        "--udp",
        "-p",
        str(HPING3_ATTACK_DPORT),
        "-d",
        str(HPING3_ATTACK_DLEN),
        "--rand-source",
        "--interface",
        args.iface,
        args.dst_ip,
    ]

    print("[METRIC] attack_backend=hping3_udp_flood")
    print(f"[METRIC] hping3_cmd={' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        print(f"[ERROR] '{HPING3_BIN}' not found. Install hping3 and retry.")
        stop_event.wait()
        return

    stop_event.wait()
    proc.terminate()
    try:
        _, stderr_bytes = proc.communicate(timeout=5)
        if stderr_bytes:
            for line in stderr_bytes.decode("utf-8", errors="ignore").strip().splitlines()[-3:]:
                if line.strip():
                    print(f"[HPING3] {line}")
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()


def signal_saturation_node(node, token, timeout):
    try:
        host, port_str = node.split(":", 1)
        port = int(port_str)
    except ValueError:
        print("[ERROR] --saturation-node must be host:port")
        return False

    try:
        payload = (token + "\n").encode("utf-8")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
            sock.settimeout(timeout)
            try:
                sock.recv(64)
            except (socket.timeout, OSError):
                pass
        print("[METRIC] saturation_signal=sent")
        return True
    except OSError as exc:
        print("[METRIC] saturation_signal=failed")
        print(f"[ERROR] saturation handshake failed: {exc}")
        return False


def collect_sample(args):
    stats = get_stats(args.controller_api) or {}
    metrics = get_attack_metrics(args.controller_api) or {}
    mitigation = metrics.get("mitigation", {}) if isinstance(metrics, dict) else {}

    trusted_sources = mitigation.get("trusted_sources", []) if isinstance(mitigation, dict) else []
    source_counts = mitigation.get("source_packet_counts", {}) if isinstance(mitigation, dict) else {}

    raw_count = source_counts.get(args.source_mac, 0)
    try:
        source_count = int(raw_count)
    except (TypeError, ValueError):
        source_count = 0

    cpu = stats.get("controller_cpu_percent")
    if isinstance(cpu, str):
        cpu = cpu.strip().rstrip("%")
        try:
            cpu = float(cpu)
        except ValueError:
            cpu = None

    return {
        "ts": time.time(),
        "pi_rate": stats.get("packet_in_rate", 0),
        "cpu": cpu if isinstance(cpu, (int, float)) else None,
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


def run_attack_window(args):
    stop_event = threading.Event()
    sender = threading.Thread(target=run_hping3_flood, args=(args, stop_event), daemon=True)
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


def parse_args():
    parser = argparse.ArgumentParser(description="Simplified trust test")
    parser.add_argument("--granularity", action="store_true", help="Signal saturation node before attack window")
    parser.add_argument("--saturation-node", default="", help="Required with --granularity; format host:port")
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--controller-api", default=DEFAULT_CONTROLLER_API)
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC)
    parser.add_argument("--dst-ip", default=DEFAULT_DST_IP)
    parser.add_argument("--source-mac", default=DEFAULT_SOURCE_MAC)
    parser.add_argument("--source-ip", default=DEFAULT_SOURCE_IP)
    parser.add_argument("--run-seconds", type=int, default=DEFAULT_RUN_SECONDS)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--benign-pps", type=int, default=DEFAULT_BENIGN_PPS)
    parser.add_argument("--trust-timeout-sec", type=int, default=DEFAULT_TRUST_TIMEOUT_SEC)
    parser.add_argument("--signal-token", default=DEFAULT_SIGNAL_TOKEN)
    parser.add_argument("--signal-timeout", type=float, default=DEFAULT_SIGNAL_TIMEOUT)
    parser.add_argument("--clear-trust", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.run_seconds <= 0 or args.poll_interval <= 0 or args.benign_pps <= 0 or args.trust_timeout_sec <= 0:
        print("ERROR: run/poll/benign/trust values must be > 0")
        sys.exit(1)

    if args.signal_timeout <= 0:
        print("ERROR: --signal-timeout must be > 0")
        sys.exit(1)

    if args.granularity and not args.saturation_node:
        print("ERROR: --granularity requires --saturation-node host:port")
        sys.exit(1)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ERROR: Requires raw-socket privileges (scapy + hping3).")
        print("       Run with: sudo python3 ./test_suite/trust_test.py ...")
        sys.exit(1)

    conf.iface = args.iface

    stats = get_stats(args.controller_api)
    if stats is None:
        print("ERROR: cannot reach controller REST API")
        sys.exit(2)

    if not reset_controller(args.controller_api):
        print("ERROR: could not reset controller state")
        sys.exit(3)

    if args.clear_trust:
        print(f"[METRIC] trust_clear_status={'ok' if clear_trust_state(args.controller_api) else 'failed'}")

    print("[PHASE] benign_wait_for_trust")
    benign_stop = threading.Event()
    benign_sender = threading.Thread(target=send_benign_until_stopped, args=(args, benign_stop), daemon=True)
    benign_sender.start()

    trust_result = wait_for_trust(args.controller_api, args.source_mac, args.trust_timeout_sec)
    benign_stop.set()
    benign_sender.join(timeout=3)

    if trust_result is None or trust_result.get("status") != "trusted":
        print(f"[METRIC] trust_status={trust_result.get('status') if trust_result else 'error'}")
        print("[ERROR] source was not trusted before timeout")
        sys.exit(4)

    print("[METRIC] trust_status=trusted")
    print(f"[METRIC] time_to_trust_sec={trust_result.get('time_to_trust', 0)}")

    if args.granularity:
        print("[PHASE] signal_saturation_node")
        if not signal_saturation_node(args.saturation_node, args.signal_token, args.signal_timeout):
            sys.exit(5)

    print("[PHASE] attack_window")
    run_attack_window(args)


if __name__ == "__main__":
    main()
