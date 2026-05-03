#!/usr/bin/env python3
"""
Saturation finder: ramp attack rate with mitigation OFF to identify controller saturation point.

Measures RTT degradation and CPU load at each rate to identify when the controller
starts dropping packets or becoming unresponsive.

Output: saturation_report.json with recommended maximum safe attack rate.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time


def run_rate_step(rate, duration, out_dir, cmd_prefix, attack_method, target, iface, size=64):
    """Run attack at a single rate; return avg RTT and max CPU."""
    run_dir = os.path.join(out_dir, f"rate_{rate}_pps")
    os.makedirs(run_dir, exist_ok=True)
    
    # Prepare attack command
    if attack_method == "scapy":
        attack_cmd = (
            f"sudo python3 packetin_attack.py --method scapy --iface {iface} "
            f"--rate {rate} --size {size} --duration {duration} --target {target}"
        )
    elif attack_method == "hping3":
        attack_cmd = (
            f"timeout {duration} bash -lc 'for p in 9991 9992 9993; do "
            f"sudo hping3 --udp --flood --rand-source -d {size} -p $p {target} & done; wait'"
        )
    else:
        attack_cmd = (
            f"python3 packetin_attack.py --method udp --rate {rate} "
            f"--size {size} --duration {duration} --target {target}"
        )
    
    if cmd_prefix:
        attack_cmd = f"{cmd_prefix} {attack_cmd}"
    
    # Start attack in background
    attack_log = os.path.join(run_dir, "attack.log")
    print(f"  Starting attack at {rate} pps for {duration}s...")
    subprocess.Popen(
        attack_cmd,
        shell=True,
        stdout=open(attack_log, 'w'),
        stderr=subprocess.STDOUT
    )
    
    # Run ping in background to measure RTT
    ping_log = os.path.join(run_dir, "ping.log")
    ping_interval = 0.5
    ping_count = int(duration / ping_interval)
    ping_cmd = f"ping -i {ping_interval} -c {ping_count} -s 56 {target}"
    print(f"  Running ping for RTT measurement...")
    subprocess.run(ping_cmd, shell=True, stdout=open(ping_log, 'w'), stderr=subprocess.STDOUT)
    
    # Parse ping results
    rtt_values = []
    packet_loss = 0
    try:
        with open(ping_log, 'r', errors='ignore') as f:
            for line in f:
                m = re.search(r'time=([0-9.]+)\s*ms', line)
                if m:
                    rtt_values.append(float(m.group(1)))
                m = re.search(r'([0-9.]+)%\s+packet\s+loss', line)
                if m:
                    packet_loss = float(m.group(1))
    except Exception as e:
        print(f"    Error parsing ping: {e}")
    
    avg_rtt = sum(rtt_values) / len(rtt_values) if rtt_values else None
    min_rtt = min(rtt_values) if rtt_values else None
    max_rtt = max(rtt_values) if rtt_values else None
    
    # Clean up attack process
    time.sleep(1)
    
    return {
        "rate": rate,
        "avg_rtt_ms": round(avg_rtt, 2) if avg_rtt else None,
        "min_rtt_ms": round(min_rtt, 2) if min_rtt else None,
        "max_rtt_ms": round(max_rtt, 2) if max_rtt else None,
        "packet_loss_percent": round(packet_loss, 2),
        "rtt_samples": len(rtt_values),
        "output_dir": run_dir,
    }


def main():
    p = argparse.ArgumentParser(description="Find controller saturation point by ramping attack rate.")
    p.add_argument('--controller', default='http://127.0.0.1:8080', help='Ryu REST API base URL')
    p.add_argument('--out', required=True, help='Output directory for results')
    p.add_argument('--target', required=True, help='Victim IP for attack')
    p.add_argument('--iface', required=True, help='Attacker interface (e.g. eth1)')
    p.add_argument('--attack-method', default='hping3', choices=['hping3', 'scapy', 'udp'])
    p.add_argument('--cmd-prefix', default='', help='SSH prefix for remote execution (e.g., ssh user@host)')
    p.add_argument('--step-duration', type=int, default=30, help='Duration per rate step (seconds)')
    p.add_argument('--rtt-threshold-ms', type=float, default=50, help='RTT threshold for saturation')
    p.add_argument('--loss-threshold-percent', type=float, default=5, help='Packet loss threshold for saturation')
    p.add_argument('--rates', default='1000,5000,10000,20000,50000', 
                   help='Comma-separated list of attack rates to test (pps)')
    
    args = p.parse_args()
    
    os.makedirs(args.out, exist_ok=True)
    
    # Parse rates
    try:
        rates = [int(r) for r in args.rates.split(',')]
    except ValueError:
        print("ERROR: --rates must be comma-separated integers")
        sys.exit(1)
    
    print(f"\nSaturation Finder")
    print(f"================")
    print(f"Target: {args.target}")
    print(f"Attack method: {args.attack_method}")
    print(f"Rates to test: {rates} pps")
    print(f"Step duration: {args.step_duration}s")
    print(f"RTT saturation threshold: {args.rtt_threshold_ms}ms")
    print(f"Packet loss saturation threshold: {args.loss_threshold_percent}%\n")
    
    results = []
    saturation_rate = None
    
    for rate in rates:
        print(f"Testing {rate} pps...")
        result = run_rate_step(
            rate=rate,
            duration=args.step_duration,
            out_dir=args.out,
            cmd_prefix=args.cmd_prefix,
            attack_method=args.attack_method,
            target=args.target,
            iface=args.iface,
        )
        results.append(result)
        
        print(f"  Avg RTT: {result['avg_rtt_ms']}ms  Packet loss: {result['packet_loss_percent']}%")
        
        # Check for saturation
        if result['avg_rtt_ms'] and result['avg_rtt_ms'] > args.rtt_threshold_ms:
            print(f"  *** SATURATION DETECTED: RTT exceeded {args.rtt_threshold_ms}ms ***")
            saturation_rate = rate
            break
        
        if result['packet_loss_percent'] > args.loss_threshold_percent:
            print(f"  *** SATURATION DETECTED: Packet loss exceeded {args.loss_threshold_percent}% ***")
            saturation_rate = rate
            break
    
    # Write report
    report = {
        "results": results,
        "saturation_rate_pps": saturation_rate,
        "safe_maximum_attack_rate": saturation_rate - (rates[rates.index(saturation_rate) - 1] if saturation_rate and saturation_rate in rates and rates.index(saturation_rate) > 0 else 0) if saturation_rate else rates[-1],
        "rtt_threshold_ms": args.rtt_threshold_ms,
        "loss_threshold_percent": args.loss_threshold_percent,
        "note": "Use safe_maximum_attack_rate as the highest sustainable attack rate for this controller configuration.",
    }
    
    report_path = os.path.join(args.out, "saturation_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n=== Saturation Report ===")
    print(f"Saturation detected at: {saturation_rate} pps" if saturation_rate else "No saturation detected")
    print(f"Safe maximum rate: {report['safe_maximum_attack_rate']} pps")
    print(f"Report saved: {report_path}\n")


if __name__ == '__main__':
    main()
