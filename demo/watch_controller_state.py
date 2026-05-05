#!/usr/bin/env python3
import argparse
import json
import sys
import time
from datetime import datetime
from urllib.error import URLError, HTTPError
from urllib.request import urlopen


def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg, fh=None):
    line = "[{}] {}".format(now_ts(), msg)
    print(line, flush=True)
    if fh:
        fh.write(line + "\n")
        fh.flush()


def fetch_json(base_url, path, timeout=3.0):
    url = base_url.rstrip("/") + path
    req = urlopen(url, timeout=timeout)
    body = req.read().decode("utf-8", errors="replace")
    return json.loads(body)


def safe_fetch(base_url, path):
    try:
        return fetch_json(base_url, path), None
    except (URLError, HTTPError, ValueError) as exc:
        return None, str(exc)


def as_switch_set(switches_payload):
    if not isinstance(switches_payload, list):
        return set()
    out = set()
    for item in switches_payload:
        if isinstance(item, dict) and "dpid" in item:
            out.add(str(item["dpid"]))
    return out


def parse_args():
    p = argparse.ArgumentParser(description="Verbose controller state watcher for demo/presentation")
    p.add_argument("--controller", default="http://127.0.0.1:8080", help="Controller REST base URL")
    p.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    p.add_argument("--duration", type=float, default=90.0, help="Total watch duration in seconds")
    p.add_argument("--log", default="", help="Optional file path to mirror output")
    p.add_argument("--mode", choices=["verbose", "flat"], default="verbose", help="Output style")
    p.add_argument("--target-pps", type=float, default=0.0, help="Expected flat attack rate in pps")
    p.add_argument("--rate-tolerance", type=float, default=0.95, help="Required fraction of target pps")
    p.add_argument("--hold-duration", type=float, default=10.0, help="Seconds that measured rate must stay above required")
    p.add_argument("--reach-timeout", type=float, default=30.0, help="Max seconds to reach and hold target")
    return p.parse_args()


def flatten_escalated_ports(escalated_payload):
    out = set()
    if not isinstance(escalated_payload, dict):
        return out

    for dpid, ports in escalated_payload.items():
        if not isinstance(ports, list):
            continue
        for port in ports:
            out.add((str(dpid), str(port)))
    return out


def run_verbose(args, fh):
    log("WATCH START controller={} interval={}s duration={}s".format(args.controller, args.interval, args.duration), fh)

    prev = {
        "switches": set(),
        "attack_detected": None,
        "mitigation_active": None,
        "mitigation_enabled": None,
        "packet_in_rate": None,
        "packet_in_threshold": None,
        "connected_switches": None,
        "known_hosts": None,
    }

    deadline = time.time() + max(0.1, args.duration)
    last_summary = 0.0

    while time.time() < deadline:
        stats, stats_err = safe_fetch(args.controller, "/stats")
        attack, attack_err = safe_fetch(args.controller, "/attack/status")
        switches, sw_err = safe_fetch(args.controller, "/switches")

        if stats_err or attack_err or sw_err:
            errs = []
            if stats_err:
                errs.append("/stats: {}".format(stats_err))
            if attack_err:
                errs.append("/attack/status: {}".format(attack_err))
            if sw_err:
                errs.append("/switches: {}".format(sw_err))
            log("WARN API fetch issue -> {}".format(" | ".join(errs)), fh)
            time.sleep(args.interval)
            continue

        switch_set = as_switch_set(switches)

        added = sorted(list(switch_set - prev["switches"]))
        removed = sorted(list(prev["switches"] - switch_set))
        if added:
            log("SWITCH CONNECTED +{}".format(",".join(added)), fh)
        if removed:
            log("SWITCH DISCONNECTED -{}".format(",".join(removed)), fh)

        cur_attack = bool(attack.get("attack_detected", False))
        cur_mit_active = bool(attack.get("mitigation_active", False))
        cur_mit_enabled = bool(attack.get("mitigation_enabled", False))
        cur_rate = float(attack.get("packet_in_rate", 0.0))
        cur_threshold = float(attack.get("threshold_rate", stats.get("packet_in_threshold", 0.0)))
        cur_sw_count = int(stats.get("connected_switches", 0))
        cur_hosts = int(stats.get("known_hosts", 0))

        if prev["attack_detected"] is None:
            log(
                "INITIAL state switches={} hosts={} packet_in_rate={:.2f} threshold={:.2f} attack_detected={} mitigation_active={} mitigation_enabled={}".format(
                    cur_sw_count,
                    cur_hosts,
                    cur_rate,
                    cur_threshold,
                    cur_attack,
                    cur_mit_active,
                    cur_mit_enabled,
                ),
                fh,
            )
        else:
            if cur_attack != prev["attack_detected"]:
                state = "DETECTED" if cur_attack else "CLEARED"
                log("ATTACK {} (rate={:.2f}, threshold={:.2f})".format(state, cur_rate, cur_threshold), fh)

            if cur_mit_active != prev["mitigation_active"]:
                state = "ACTIVE" if cur_mit_active else "INACTIVE"
                log("MITIGATION {}".format(state), fh)

            if cur_mit_enabled != prev["mitigation_enabled"]:
                state = "ENABLED" if cur_mit_enabled else "DISABLED"
                log("MITIGATION CONFIG {}".format(state), fh)

            if cur_sw_count != prev["connected_switches"]:
                log("SWITCH COUNT {} -> {}".format(prev["connected_switches"], cur_sw_count), fh)

            if cur_hosts != prev["known_hosts"]:
                log("HOST COUNT {} -> {}".format(prev["known_hosts"], cur_hosts), fh)

            prev_rate = prev["packet_in_rate"]
            if prev_rate is not None:
                delta = cur_rate - prev_rate
                if abs(delta) >= max(5.0, cur_threshold * 0.05):
                    log("PACKET_IN_RATE jump {:.2f} -> {:.2f} (delta={:+.2f})".format(prev_rate, cur_rate, delta), fh)

        if cur_threshold > 0 and cur_rate >= cur_threshold:
            log("ALERT packet_in_rate {:.2f} >= threshold {:.2f}".format(cur_rate, cur_threshold), fh)

        if time.time() - last_summary >= 5.0:
            log(
                "HEARTBEAT switches={} hosts={} rate={:.2f} threshold={:.2f} attack={} mitigation={}".format(
                    cur_sw_count,
                    cur_hosts,
                    cur_rate,
                    cur_threshold,
                    cur_attack,
                    cur_mit_active,
                ),
                fh,
            )
            last_summary = time.time()

        prev["switches"] = switch_set
        prev["attack_detected"] = cur_attack
        prev["mitigation_active"] = cur_mit_active
        prev["mitigation_enabled"] = cur_mit_enabled
        prev["packet_in_rate"] = cur_rate
        prev["packet_in_threshold"] = cur_threshold
        prev["connected_switches"] = cur_sw_count
        prev["known_hosts"] = cur_hosts

        time.sleep(max(0.2, args.interval))

    log("WATCH END", fh)


def run_flat(args, fh):
    required_rate = max(0.0, args.target_pps * args.rate_tolerance)
    start = time.time()
    deadline = start + max(0.1, args.duration)

    samples = 0
    pi_sum = 0.0
    cpu_sum = 0.0
    pi_peak = 0.0
    cpu_peak = 0.0

    prev_mitigation = None
    prev_escalated = set()
    saw_threshold = False
    saw_mitigation_active = False
    saw_port_closed = False
    saw_back_to_meter = False
    saw_back_to_normal = False

    normal_start = None
    normal_hold_seconds = max(3.0, args.interval * 3)

    log("Mode          : FLAT", fh)
    log("Target PPS    : {} pps".format(int(args.target_pps) if args.target_pps >= 1 else args.target_pps), fh)
    log("Rate tolerance: {:.0f}% of target".format(args.rate_tolerance * 100.0), fh)
    log("Goal          : threshold -> mitigation -> port close -> recovery", fh)
    log("", fh)
    log("  Target PPS   Avg PI Rate   Avg CPU %", fh)
    log("--------------------------------------", fh)
    log("", fh)

    while time.time() < deadline:
        stats, stats_err = safe_fetch(args.controller, "/stats")
        attack, attack_err = safe_fetch(args.controller, "/attack/status")
        metrics, metrics_err = safe_fetch(args.controller, "/attack/metrics")

        if stats_err or attack_err or metrics_err:
            errs = []
            if stats_err:
                errs.append("/stats: {}".format(stats_err))
            if attack_err:
                errs.append("/attack/status: {}".format(attack_err))
            if metrics_err:
                errs.append("/attack/metrics: {}".format(metrics_err))
            log("WARN API fetch issue -> {}".format(" | ".join(errs)), fh)
            time.sleep(max(0.2, args.interval))
            continue

        pi_rate = float(attack.get("packet_in_rate", stats.get("packet_in_rate", 0.0)))
        cpu = float(stats.get("controller_cpu_percent", 0.0))
        mitigation_active = bool(attack.get("mitigation_active", False))

        mitigation_obj = metrics.get("mitigation", {}) if isinstance(metrics, dict) else {}
        escalated = flatten_escalated_ports(mitigation_obj.get("escalated_ports", {}))

        samples += 1
        pi_sum += pi_rate
        cpu_sum += cpu
        pi_peak = max(pi_peak, pi_rate)
        cpu_peak = max(cpu_peak, cpu)

        log(
            "  target={} pps  measured pi_rate={:.2f}/s  cpu={:.2f}%".format(
                int(args.target_pps) if args.target_pps >= 1 else args.target_pps,
                pi_rate,
                cpu,
            ),
            fh,
        )

        if not saw_threshold and required_rate > 0.0 and pi_rate >= required_rate:
            saw_threshold = True
            log("ALERT threshold reached: pi_rate {:.2f}/s >= {:.2f}/s".format(pi_rate, required_rate), fh)

        if prev_mitigation is None:
            prev_mitigation = mitigation_active
            if mitigation_active:
                saw_mitigation_active = True
        elif mitigation_active != prev_mitigation:
            state = "ACTIVE" if mitigation_active else "INACTIVE"
            log("ALERT mitigation {}".format(state), fh)
            prev_mitigation = mitigation_active
            if mitigation_active:
                saw_mitigation_active = True

        new_escalated = sorted(escalated - prev_escalated)
        for dpid, port in new_escalated:
            log("ALERT port fully closed: dpid={} port={}".format(dpid, port), fh)
            saw_port_closed = True

        if saw_port_closed and prev_escalated and not escalated and mitigation_active and not saw_back_to_meter:
            saw_back_to_meter = True
            log("ALERT lockdown lifted: back to meter mode", fh)

        prev_escalated = escalated

        if saw_mitigation_active and not escalated and not mitigation_active:
            if normal_start is None:
                normal_start = time.time()
            elif time.time() - normal_start >= normal_hold_seconds:
                saw_back_to_normal = True
        else:
            normal_start = None

        # Full end-to-end transition reached.
        if saw_threshold and saw_mitigation_active and saw_port_closed and (saw_back_to_meter or saw_back_to_normal):
            break

        time.sleep(max(0.2, args.interval))

    avg_pi = (pi_sum / samples) if samples else 0.0
    avg_cpu = (cpu_sum / samples) if samples else 0.0

    log("", fh)
    log("==================================================================", fh)
    log("  Target PPS   Avg PI Rate   Peak PI Rate   Avg CPU %   Peak CPU %", fh)
    log("------------------------------------------------------------------", fh)
    log(
        "{:12.0f}{:14.2f}{:15.2f}{:12.2f}{:12.2f}".format(
            args.target_pps,
            avg_pi,
            pi_peak,
            avg_cpu,
            cpu_peak,
        ),
        fh,
    )
    log("==================================================================", fh)
    if saw_threshold and saw_mitigation_active and saw_port_closed and (saw_back_to_meter or saw_back_to_normal):
        log("RESULT: PASS (observed threshold -> mitigation -> lockdown -> recovery transition)", fh)
    else:
        missing = []
        if not saw_threshold:
            missing.append("threshold reached")
        if not saw_mitigation_active:
            missing.append("mitigation active")
        if not saw_port_closed:
            missing.append("port fully closed")
        if not (saw_back_to_meter or saw_back_to_normal):
            missing.append("recovery (meter/normal)")
        log("RESULT: PARTIAL (missing: {})".format(", ".join(missing)), fh)


def main():
    args = parse_args()
    fh = open(args.log, "w", encoding="utf-8") if args.log else None

    if args.mode == "flat":
        run_flat(args, fh)
    else:
        run_verbose(args, fh)

    log("WATCH END", fh)
    if fh:
        fh.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[{}] WATCH INTERRUPTED".format(now_ts()))
        sys.exit(130)
