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
    return p.parse_args()


def main():
    args = parse_args()
    fh = open(args.log, "w", encoding="utf-8") if args.log else None

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
    if fh:
        fh.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[{}] WATCH INTERRUPTED".format(now_ts()))
        sys.exit(130)
