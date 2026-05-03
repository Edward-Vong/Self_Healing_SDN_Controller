#!/usr/bin/env python3
"""Create cross-run summary CSVs and graphs from result folders.

Usage:
  python3 summarize_runs.py results --output results/summary
"""

import argparse
import csv
import json
import os
import re
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def fnum(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default


def avg(values):
    vals = [v for v in values if v is not None]
    return statistics.mean(vals) if vals else 0.0


def maxv(values):
    vals = [v for v in values if v is not None]
    return max(vals) if vals else 0.0


def parse_ping_csv_or_log(run_dir, name):
    csv_path = run_dir / f"{name}.csv"
    rows = read_csv(csv_path)
    if rows:
        return [(fnum(r.get("t")), fnum(r.get("rtt_ms"))) for r in rows]

    log_path = run_dir / f"{name}.log"
    if not log_path.exists():
        return []
    out = []
    idx = 0
    with log_path.open(errors="ignore") as f:
        for line in f:
            m = re.search(r"time=([0-9.]+)\s*ms", line)
            if m:
                out.append((idx * 0.5, float(m.group(1))))
                idx += 1
    return out


def parse_iperf_log(run_dir, name):
    path = run_dir / f"{name}.log"
    if not path.exists():
        return []
    vals = []
    with path.open(errors="ignore") as f:
        for line in f:
            if "bits/sec" not in line:
                continue
            m = re.search(r"([0-9.]+)\s+([KMG])?bits/sec", line)
            if not m:
                continue
            val = float(m.group(1))
            unit = m.group(2) or ""
            if unit == "K":
                val /= 1000.0
            elif unit == "G":
                val *= 1000.0
            vals.append(val)
    return vals


def summarize_run(run_dir):
    cfg_path = run_dir / "config.json"
    if not cfg_path.exists():
        return None
    with cfg_path.open() as f:
        cfg = json.load(f)

    attack_delay = fnum(cfg.get("attack_delay"), 30)
    attack_length_raw = cfg.get("attack_length")
    duration = fnum(cfg.get("duration"), 180)
    attack_length = fnum(attack_length_raw, duration - attack_delay) if str(attack_length_raw) else duration - attack_delay
    attack_end = attack_delay + attack_length

    metrics = read_csv(run_dir / "controller_metrics.csv")
    status = read_csv(run_dir / "attack_status.csv")
    mit = read_csv(run_dir / "mitigation_metrics.csv")

    attack_metrics = [r for r in metrics if attack_delay <= fnum(r.get("t")) <= attack_end]
    attack_status = [r for r in status if attack_delay <= fnum(r.get("t")) <= attack_end]

    ping_existing = [(t, rtt) for t, rtt in parse_ping_csv_or_log(run_dir, "ping_existing") if attack_delay <= t <= attack_end]
    ping_new = [(t, rtt) for t, rtt in parse_ping_csv_or_log(run_dir, "ping_new") if attack_delay <= t <= attack_end]

    iperf_existing = parse_iperf_log(run_dir, "iperf_existing")
    iperf_new = parse_iperf_log(run_dir, "iperf_new")

    last_mit = mit[-1] if mit else {}

    return {
        "run_dir": str(run_dir),
        "name": cfg.get("name", run_dir.name),
        "rate": fnum(cfg.get("rate")),
        "size": fnum(cfg.get("size")),
        "mitigation": cfg.get("mitigation", ""),
        "attack_method": cfg.get("attack_method", ""),
        "duration": duration,
        "attack_delay": attack_delay,
        "attack_length": attack_length,
        "avg_cpu_attack": round(avg([fnum(r.get("controller_cpu_percent")) for r in attack_metrics]), 4),
        "max_cpu_attack": round(maxv([fnum(r.get("controller_cpu_percent")) for r in attack_metrics]), 4),
        "avg_packetin_attack": round(avg([fnum(r.get("packet_in_rate")) for r in attack_status]), 4),
        "max_packetin_attack": round(maxv([fnum(r.get("packet_in_rate")) for r in attack_status]), 4),
        "avg_rtt_existing_attack_ms": round(avg([rtt for _, rtt in ping_existing]), 4),
        "avg_rtt_new_attack_ms": round(avg([rtt for _, rtt in ping_new]), 4),
        "avg_iperf_existing_mbps": round(avg(iperf_existing), 4),
        "avg_iperf_new_mbps": round(avg(iperf_new), 4),
        "mitigated_drop_count": fnum(last_mit.get("mitigated_drop_count")),
        "dropped_unknown_count": fnum(last_mit.get("dropped_unknown_count")),
        "dropped_overrate_count": fnum(last_mit.get("dropped_overrate_count")),
    }


def write_summary(rows, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_csv = out_dir / "cross_run_summary.csv"
    fields = list(rows[0].keys()) if rows else []
    with summary_csv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return summary_csv


def plot_xy(rows, xkey, ykey, title, ylabel, out_path, filter_fn):
    data = [r for r in rows if filter_fn(r)]
    data = sorted(data, key=lambda r: fnum(r.get(xkey)))
    if len(data) < 2:
        return False
    plt.figure(figsize=(10, 6))
    plt.plot([r[xkey] for r in data], [r[ykey] for r in data], marker="o")
    plt.xlabel(xkey)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir")
    ap.add_argument("--output", default="")
    args = ap.parse_args()

    root = Path(args.results_dir)
    out_dir = Path(args.output) if args.output else root / "summary"
    rows = []
    for d in sorted(root.iterdir()):
        if d.is_dir():
            row = summarize_run(d)
            if row:
                rows.append(row)

    if not rows:
        raise SystemExit("No result folders with config.json found.")

    summary_csv = write_summary(rows, out_dir)
    made = [summary_csv]

    # Rate sweep: compare only runs where size, mitigation, and method are constant.
    for ykey, ylabel in [
        ("avg_cpu_attack", "avg CPU during attack (%)"),
        ("avg_packetin_attack", "avg Packet-In rate during attack"),
        ("avg_rtt_existing_attack_ms", "existing trusted RTT during attack (ms)"),
        ("avg_rtt_new_attack_ms", "new trusted RTT during attack (ms)"),
        ("avg_iperf_existing_mbps", "existing trusted throughput (Mbits/sec)"),
        ("mitigated_drop_count", "total mitigated drops"),
    ]:
        out = out_dir / f"rate_vs_{ykey}.png"
        ok = plot_xy(
            rows,
            "rate",
            ykey,
            f"Rate sweep: {ykey}",
            ylabel,
            out,
            lambda r: r.get("mitigation") == "on" and fnum(r.get("size")) == 64,
        )
        if ok:
            made.append(out)

    # Size sweep: compare only runs where rate and mitigation are constant.
    for ykey, ylabel in [
        ("avg_cpu_attack", "avg CPU during attack (%)"),
        ("avg_packetin_attack", "avg Packet-In rate during attack"),
        ("avg_rtt_existing_attack_ms", "existing trusted RTT during attack (ms)"),
        ("avg_rtt_new_attack_ms", "new trusted RTT during attack (ms)"),
        ("avg_iperf_existing_mbps", "existing trusted throughput (Mbits/sec)"),
    ]:
        out = out_dir / f"size_vs_{ykey}.png"
        ok = plot_xy(
            rows,
            "size",
            ykey,
            f"Packet size sweep: {ykey}",
            ylabel,
            out,
            lambda r: r.get("mitigation") == "on" and fnum(r.get("rate")) == 10000,
        )
        if ok:
            made.append(out)

    with (out_dir / "summary_outputs.txt").open("w") as f:
        for p in made:
            f.write(str(p) + "\n")

    print("\n".join(str(p) for p in made))


if __name__ == "__main__":
    main()
