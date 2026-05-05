#!/usr/bin/env python3
"""
Saturation finder: ramp attack rate with mitigation OFF to identify controller saturation point.

Measures RTT degradation and CPU load at each rate to identify when the controller
starts dropping packets or becoming unresponsive.

Output: saturation_report.json with recommended maximum safe attack rate.
"""

import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request


def _to_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default


def _read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def summarize_controller_metrics(run_dir):
    """Summarize sampled controller/mitigation metrics for one rate step."""
    status_rows = _read_csv(os.path.join(run_dir, 'attack_status.csv'))
    mit_rows = _read_csv(os.path.join(run_dir, 'mitigation_metrics.csv'))

    max_packet_in_rate = max((_to_float(r.get('packet_in_rate')) for r in status_rows), default=0.0)
    mitigation_active_samples = sum(1 for r in status_rows if str(r.get('mitigation_active', '')).lower() in ('true', '1', 'yes', 'on'))
    max_rate_limited_ports = max((_to_float(r.get('rate_limited_ports_count')) for r in mit_rows), default=0.0)
    max_escalated_ports = max((_to_float(r.get('escalated_ports_count')) for r in mit_rows), default=0.0)

    return {
        'samples_collected': len(status_rows),
        'max_packet_in_rate': round(max_packet_in_rate, 2),
        'mitigation_active_samples': mitigation_active_samples,
        'max_rate_limited_ports_count': int(max_rate_limited_ports),
        'max_escalated_ports_count': int(max_escalated_ports),
    }


def run_rate_step(
    rate,
    duration,
    out_dir,
    cmd_prefix,
    attack_method,
    target,
    iface,
    size=256,
    rtt_cmd_prefix='',
    python_bin='python3',
    controller='http://127.0.0.1:8080',
    collect_controller_metrics=True,
    controller_iface='',
    switch_ips='',
):
    """Run attack at a single rate; return avg RTT and max CPU."""
    run_dir = os.path.join(out_dir, "rate_{}_pps".format(rate))
    os.makedirs(run_dir, exist_ok=True)
    
    # Prepare attack command
    if attack_method == "scapy":
        attack_cmd = (
            "cd '{script_dir}' && sudo {python} packetin_attack.py --method scapy --iface {iface} "
            "--rate {rate} --size {size} --duration {dur} --target {target}".format(
                script_dir=os.path.dirname(os.path.abspath(__file__)),
                python=python_bin,
                iface=iface, rate=rate, size=size, dur=duration, target=target)
        )
    elif attack_method == "hping3":
        attack_cmd = (
            "timeout {} bash -lc 'for p in 9991 9992 9993; do "
            "sudo hping3 --udp --flood --rand-source -d {} -p $p {} & done; wait'".format(duration, size, target)
        )
    else:
        attack_cmd = (
            "{} packetin_attack.py --method udp --rate {} "
            "--size {} --duration {} --target {}".format(python_bin, rate, size, duration, target)
        )
    
    if cmd_prefix:
        # Pass the entire remote command as one SSH argument so bash -lc loops
        # are not dequoted/split by remote shell reconstruction.
        attack_cmd = "{} {}".format(cmd_prefix, shlex.quote(attack_cmd))
    
    # Start optional metrics collection in background so mitigation transitions are sampled.
    collector_proc = None
    if collect_controller_metrics:
        collector_cmd = [
            sys.executable,
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'collect_metrics.py'),
            '--duration', str(duration),
            '--interval', '1.0',
            '--out', run_dir,
            '--controller', controller,
            '--controller-wait', '5',
        ]
        if controller_iface:
            collector_cmd.extend(['--iface', controller_iface])
        if switch_ips:
            collector_cmd.extend(['--switch-ips', switch_ips])

        collector_log = os.path.join(run_dir, 'collector.log')
        with open(collector_log, 'w') as collector_fh:
            collector_proc = subprocess.Popen(
                collector_cmd,
                stdout=collector_fh,
                stderr=subprocess.STDOUT,
            )

    # Start attack in background
    attack_log = os.path.join(run_dir, "attack.log")
    print("  Starting attack at {} pps for {}s...".format(rate, duration))
    with open(attack_log, 'w') as attack_log_fh:
        subprocess.Popen(
            attack_cmd,
            shell=True,
            stdout=attack_log_fh,
            stderr=subprocess.STDOUT
        )
    
    # Warm up ARP/flow-table before measurement so the first ping isn't a cold miss.
    if rtt_cmd_prefix:
        warmup_cmd = "{} 'ping -c 3 -W 2 -q {}'".format(rtt_cmd_prefix, target)
    else:
        warmup_cmd = "ping -c 3 -W 2 -q {}".format(target)
    subprocess.run(warmup_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Run ping for RTT measurement. If rtt_cmd_prefix is provided (e.g. 'ssh user@trusted'),
    # run the ping on that remote node so it probes the dataplane from inside the experiment LAN.
    ping_log = os.path.join(run_dir, "ping.log")
    ping_interval = 0.5
    ping_count = int(duration / ping_interval)
    raw_ping = "ping -i {} -c {} -s 56 {}".format(ping_interval, ping_count, target)
    if rtt_cmd_prefix:
        ping_cmd = "{} '{}'".format(rtt_cmd_prefix, raw_ping)
    else:
        ping_cmd = raw_ping
    print("  Running ping for RTT measurement...")
    subprocess.run(ping_cmd, shell=True, stdout=open(ping_log, 'w'), stderr=subprocess.STDOUT)
    
    # Parse ping results
    rtt_values = []
    packet_loss = 0
    try:
        with open(ping_log, 'r', errors='ignore') as f:
            for line in f:
                m = re.search(r'time[=<]([0-9.]+)\s*ms', line)
                if m:
                    rtt_values.append(float(m.group(1)))
                m = re.search(r'([0-9.]+)%\s+packet\s+loss', line)
                if m:
                    packet_loss = float(m.group(1))
    except Exception as e:
        print("    Error parsing ping: {}".format(e))
    
    avg_rtt = sum(rtt_values) / len(rtt_values) if rtt_values else None
    min_rtt = min(rtt_values) if rtt_values else None
    max_rtt = max(rtt_values) if rtt_values else None
    
    # Ensure collector has time to flush final rows.
    if collector_proc is not None:
        try:
            collector_proc.wait(timeout=duration + 10)
        except subprocess.TimeoutExpired:
            collector_proc.terminate()

    # Clean up attack process
    time.sleep(1)

    result = {
        "rate": rate,
        "avg_rtt_ms": round(avg_rtt, 2) if avg_rtt else None,
        "min_rtt_ms": round(min_rtt, 2) if min_rtt else None,
        "max_rtt_ms": round(max_rtt, 2) if max_rtt else None,
        "packet_loss_percent": round(packet_loss, 2),
        "rtt_samples": len(rtt_values),
        "output_dir": run_dir,
    }

    if collect_controller_metrics:
        result.update(summarize_controller_metrics(run_dir))

    return result


def set_controller_mitigation(controller_base, enabled):
    """Best-effort toggle for controller mitigation mode via REST."""
    body = json.dumps({"enabled": bool(enabled)}).encode('utf-8')
    req = urllib.request.Request(
        controller_base.rstrip('/') + '/config/mitigation',
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode('utf-8'))


def main():
    p = argparse.ArgumentParser(description="Find controller saturation point by ramping attack rate.")
    p.add_argument('--controller', default='http://127.0.0.1:8080', help='Ryu REST API base URL')
    p.add_argument('--out', required=True, help='Output directory for results')
    p.add_argument('--target', required=True, help='Victim IP for attack')
    p.add_argument('--iface', required=True, help='Attacker interface (e.g. eth1)')
    p.add_argument('--attack-method', default='hping3', choices=['hping3', 'scapy', 'udp'])
    p.add_argument('--cmd-prefix', default='', help='SSH prefix for remote execution (e.g., ssh user@host)')
    p.add_argument('--rtt-cmd-prefix', default='', help='SSH prefix for RTT ping (e.g., ssh user@trusted-node). If empty, ping runs locally on the controller.')
    p.add_argument('--step-duration', type=int, default=30, help='Duration per rate step (seconds)')
    p.add_argument('--rtt-threshold-ms', type=float, default=50, help='RTT threshold for saturation')
    p.add_argument('--loss-threshold-percent', type=float, default=5, help='Packet loss threshold for saturation')
    p.add_argument('--rates', default='1000,5000,10000,20000,50000',
                   help='Comma-separated list of attack rates to test (pps)')
    p.add_argument('--size', type=int, default=256, help='Packet size in bytes for the attack')
    p.add_argument('--python-bin', default='python3', help='Python interpreter on the attacker node (for scapy/udp methods)')
    p.add_argument(
        '--mitigation-mode',
        default='keep',
        choices=['keep', 'on', 'off'],
        help='Controller mitigation mode for this saturation run: keep current, force on, or force off'
    )
    p.add_argument('--controller-iface', default='', help='Controller interface for collect_metrics link-rate tracking')
    p.add_argument('--switch-ips', default='', help='Comma-separated IPs for switch RTT probing during each step')
    p.add_argument('--no-collect-metrics', action='store_true', help='Disable controller/mitigation metrics collection during saturation steps')

    args = p.parse_args()
    
    os.makedirs(args.out, exist_ok=True)
    
    # Parse rates
    try:
        rates = [int(r) for r in args.rates.split(',')]
    except ValueError:
        print("ERROR: --rates must be comma-separated integers")
        sys.exit(1)
    
    print("\nSaturation Finder")
    print("================")
    print("Target: {}".format(args.target))
    print("Attack method: {}".format(args.attack_method))
    print("Rates to test: {} pps".format(rates))
    print("Step duration: {}s".format(args.step_duration))
    print("RTT saturation threshold: {}ms".format(args.rtt_threshold_ms))
    print("Packet loss saturation threshold: {}%\n".format(args.loss_threshold_percent))

    if args.mitigation_mode in ('on', 'off'):
        try:
            res = set_controller_mitigation(args.controller, args.mitigation_mode == 'on')
            print("Mitigation mode set to {} ({})".format(args.mitigation_mode, res.get('result', 'ok')))
        except (urllib.error.URLError, ValueError, TimeoutError) as e:
            print("[WARN] Could not set mitigation mode to {}: {}".format(args.mitigation_mode, e))
    
    results = []
    saturation_rate = None
    
    for rate in rates:
        print("Testing {} pps...".format(rate))
        result = run_rate_step(
            rate=rate,
            duration=args.step_duration,
            out_dir=args.out,
            cmd_prefix=args.cmd_prefix,
            attack_method=args.attack_method,
            target=args.target,
            iface=args.iface,
            size=args.size,
            rtt_cmd_prefix=args.rtt_cmd_prefix,
            python_bin=args.python_bin,
            controller=args.controller,
            collect_controller_metrics=(not args.no_collect_metrics),
            controller_iface=args.controller_iface,
            switch_ips=args.switch_ips,
        )
        results.append(result)
        
        print("  Avg RTT: {}ms  Packet loss: {}%".format(result['avg_rtt_ms'], result['packet_loss_percent']))
        
        # Check for saturation
        if result['avg_rtt_ms'] and result['avg_rtt_ms'] > args.rtt_threshold_ms:
            print("  *** SATURATION DETECTED: RTT exceeded {}ms ***".format(args.rtt_threshold_ms))
            saturation_rate = rate
            break
        
        if result['packet_loss_percent'] > args.loss_threshold_percent:
            print("  *** SATURATION DETECTED: Packet loss exceeded {}% ***".format(args.loss_threshold_percent))
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
    
    print("\n=== Saturation Report ===")
    print("Saturation detected at: {} pps".format(saturation_rate) if saturation_rate else "No saturation detected")
    print("Safe maximum rate: {} pps".format(report['safe_maximum_attack_rate']))
    print("Report saved: {}\n".format(report_path))


if __name__ == '__main__':
    main()
