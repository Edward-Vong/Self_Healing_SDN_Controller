#!/usr/bin/env python3
"""Plot existing trusted-flow RTT for all rate_* experiment runs.

The output graph overlays one RTT line per rate run so Packet-In/load
differences can be compared against legitimate traffic latency.
"""
import argparse
import csv
import json
import os
import re
import sys
import html
import statistics
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    _HAS_MPL = True
except ImportError:
    plt = None
    _HAS_MPL = False


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", errors="ignore") as f:
        return list(csv.DictReader(f))


def fnum(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def resolve(run_dir, subdir, name):
    preferred = run_dir / subdir / name
    return preferred if preferred.exists() else run_dir / name


def load_config(run_dir):
    path = run_dir / "config.json"
    if not path.exists():
        return {}
    try:
        with path.open(errors="ignore") as f:
            return json.load(f)
    except Exception as exc:
        print("[WARN] Skipping config for {}: {}".format(run_dir, exc), file=sys.stderr)
        return {}


def rate_from_run(run_dir):
    cfg = load_config(run_dir)
    rate = fnum(cfg.get("rate"), None)
    if rate is not None:
        return int(rate)
    match = re.search(r"rate_(\d+)", run_dir.name)
    return int(match.group(1)) if match else 0


def parse_existing_rtt(run_dir, ping_interval=0.5):
    csv_path = resolve(run_dir, "csv", "ping_existing.csv")
    rows = read_csv(csv_path)
    if rows:
        return [(fnum(r.get("t")), fnum(r.get("rtt_ms"))) for r in rows if r.get("rtt_ms") not in ("", None)]

    log_path = resolve(run_dir, "logs", "ping_existing.log")
    if not log_path.exists():
        return []

    parsed = []
    idx = 0
    with log_path.open(errors="ignore") as f:
        for line in f:
            match = re.search(r"time=([0-9.]+)\s*ms", line)
            if not match:
                continue
            parsed.append((idx * ping_interval, float(match.group(1))))
            idx += 1
    return parsed


def parse_packet_in_series(run_dir):
    rows = read_csv(resolve(run_dir, "csv", "attack_status.csv"))
    return [(fnum(r.get("t")), fnum(r.get("packet_in_rate"))) for r in rows if r.get("packet_in_rate") not in ("", None)]


def nearest_packet_in(t, packet_in_points):
    if not packet_in_points:
        return ""
    best_t, best_rate = min(packet_in_points, key=lambda p: abs(p[0] - t))
    if abs(best_t - t) > 2.0:
        return ""
    return best_rate


def write_svg(output_path, series, title="Existing trusted-flow RTT across Scapy Packet-In rate sweep"):
    width = 1200
    height = 720
    left = 80
    right = 230
    top = 55
    bottom = 70
    plot_w = width - left - right
    plot_h = height - top - bottom

    all_points = [point for _rate, _run_dir, points in series for point in points]
    max_t = max((t for t, _rtt in all_points), default=1.0)
    max_rtt = max((rtt for _t, rtt in all_points), default=1.0)
    max_rtt = max(1.0, max_rtt * 1.10)

    palette = [
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728",
        "#9467bd", "#8c564b", "#e377c2", "#17becf",
    ]

    def xscale(t):
        return left + (t / max_t) * plot_w

    def yscale(rtt):
        return top + plot_h - (rtt / max_rtt) * plot_h

    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">'.format(width, height, width, height),
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="{}" y="30" font-family="Arial" font-size="22" font-weight="700">{}</text>'.format(left, html.escape(title)),
        '<line x1="{0}" y1="{1}" x2="{2}" y2="{1}" stroke="#222"/>'.format(left, top + plot_h, left + plot_w),
        '<line x1="{0}" y1="{1}" x2="{0}" y2="{2}" stroke="#222"/>'.format(left, top, top + plot_h),
    ]

    for i in range(6):
        y_val = max_rtt * i / 5.0
        y = yscale(y_val)
        lines.append('<line x1="{0}" y1="{1:.2f}" x2="{2}" y2="{1:.2f}" stroke="#ddd"/>'.format(left, y, left + plot_w))
        lines.append('<text x="{}" y="{:.2f}" font-family="Arial" font-size="12" text-anchor="end">{:.1f}</text>'.format(left - 8, y + 4, y_val))

    for i in range(6):
        t_val = max_t * i / 5.0
        x = xscale(t_val)
        lines.append('<line x1="{0:.2f}" y1="{1}" x2="{0:.2f}" y2="{2}" stroke="#ddd"/>'.format(x, top, top + plot_h))
        lines.append('<text x="{:.2f}" y="{}" font-family="Arial" font-size="12" text-anchor="middle">{:.0f}</text>'.format(x, top + plot_h + 22, t_val))

    lines.append('<text x="{}" y="{}" font-family="Arial" font-size="14" text-anchor="middle">time (s)</text>'.format(left + plot_w / 2, height - 20))
    lines.append('<text x="22" y="{}" font-family="Arial" font-size="14" text-anchor="middle" transform="rotate(-90 22,{})">RTT ms</text>'.format(top + plot_h / 2, top + plot_h / 2))

    for idx, (rate, _run_dir, points) in enumerate(series):
        color = palette[idx % len(palette)]
        path = " ".join(
            "{} {:.2f},{:.2f}".format("M" if j == 0 else "L", xscale(t), yscale(rtt))
            for j, (t, rtt) in enumerate(points)
        )
        lines.append('<path d="{}" fill="none" stroke="{}" stroke-width="2"/>'.format(path, color))
        legend_y = top + 25 + idx * 24
        legend_x = left + plot_w + 35
        lines.append('<line x1="{0}" y1="{1}" x2="{2}" y2="{1}" stroke="{3}" stroke-width="3"/>'.format(legend_x, legend_y, legend_x + 25, color))
        lines.append('<text x="{}" y="{}" font-family="Arial" font-size="13">{} pps</text>'.format(legend_x + 35, legend_y + 4, html.escape(str(rate))))

    lines.append("</svg>")
    output_path.write_text("\n".join(lines), encoding="utf-8")


def fit_line(points):
    if len(points) < 2:
        return None
    xs = [t for t, _rtt in points]
    ys = [rtt for _t, rtt in points]
    n = float(len(points))
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom == 0:
        return None
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denom
    intercept = mean_y - slope * mean_x
    return intercept, slope, mean_y


def rolling_trend(points, window=9):
    if not points:
        return []
    if window < 3:
        window = 3
    if window % 2 == 0:
        window += 1
    half = window // 2
    smoothed = []
    for i, (t, _rtt) in enumerate(points):
        start = max(0, i - half)
        end = min(len(points), i + half + 1)
        vals = [rtt for _t, rtt in points[start:end]]
        smoothed.append((t, statistics.median(vals)))
    return smoothed


def best_fit_series(series):
    fitted = []
    for rate, run_dir, points in series:
        fit = fit_line(points)
        if fit is None:
            continue
        intercept, slope, mean_rtt = fit
        min_t = min(t for t, _rtt in points)
        max_t = max(t for t, _rtt in points)
        fitted_points = [
            (min_t, intercept + slope * min_t),
            (max_t, intercept + slope * max_t),
        ]
        fitted.append((rate, run_dir, fitted_points, intercept, slope, mean_rtt))
    return fitted


def rolling_trend_series(series, window=9):
    trends = []
    for rate, run_dir, points in series:
        trend_points = rolling_trend(points, window=window)
        if len(trend_points) >= 2:
            trends.append((rate, run_dir, trend_points))
    return trends


def write_best_fit_svg(output_path, fitted):
    if not fitted:
        return
    svg_series = [(rate, run_dir, points) for rate, run_dir, points, _intercept, _slope, _mean_rtt in fitted]
    write_svg(output_path, svg_series, title="Best-fit RTT trends for existing trusted flow across rate sweep")


def write_rolling_trend_svg(output_path, trends, window):
    write_svg(
        output_path,
        trends,
        title="Rolling median RTT trend for existing trusted flow ({} samples)".format(window),
    )


def discover_rate_runs(results_dir):
    if not results_dir.exists():
        return []
    runs = []
    for run_dir in results_dir.iterdir():
        if not run_dir.is_dir():
            continue
        if not run_dir.name.startswith("rate_"):
            continue
        if not (run_dir / "config.json").exists():
            continue
        runs.append(run_dir)
    return sorted(runs, key=rate_from_run)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir", nargs="?", default="results")
    parser.add_argument("--output", default="", help="Output PNG path")
    parser.add_argument("--csv-output", default="", help="Output CSV path for combined samples")
    parser.add_argument("--trim-start", type=float, default=5.0)
    parser.add_argument("--max-rtt-ms", type=float, default=0.0, help="Optional y-axis cap")
    parser.add_argument("--smooth-window", type=int, default=9, help="Odd sample count for rolling median trend")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        print("[ERROR] Results directory does not exist: {}".format(results_dir), file=sys.stderr)
        sys.exit(1)

    output = Path(args.output) if args.output else results_dir / "summary" / "rate_sweep_existing_trusted_rtt.png"
    csv_output = Path(args.csv_output) if args.csv_output else output.with_suffix(".csv")
    svg_output = output.with_suffix(".svg")
    fit_output = output.with_name(output.stem + "_best_fit" + output.suffix)
    fit_svg_output = fit_output.with_suffix(".svg")
    fit_csv_output = output.with_name(output.stem + "_best_fit.csv")
    trend_output = output.with_name(output.stem + "_rolling_trend" + output.suffix)
    trend_svg_output = trend_output.with_suffix(".svg")
    trend_csv_output = output.with_name(output.stem + "_rolling_trend.csv")
    output.parent.mkdir(parents=True, exist_ok=True)

    series = []
    combined_rows = []
    for run_dir in discover_rate_runs(results_dir):
        rate = rate_from_run(run_dir)
        packet_in_points = parse_packet_in_series(run_dir)
        points = [(t, rtt) for t, rtt in parse_existing_rtt(run_dir) if t >= args.trim_start]
        if points:
            series.append((rate, run_dir, points))
            for t, rtt in points:
                combined_rows.append({
                    "run": run_dir.name,
                    "configured_attack_rate_pps": rate,
                    "t": round(t, 3),
                    "existing_trusted_rtt_ms": round(rtt, 4),
                    "packet_in_rate": nearest_packet_in(t, packet_in_points),
                })

    if not series:
        print("[ERROR] No rate_* runs with existing trusted RTT data found in {}".format(results_dir), file=sys.stderr)
        sys.exit(1)

    csv_output.parent.mkdir(parents=True, exist_ok=True)
    with csv_output.open("w", newline="") as f:
        fields = ["run", "configured_attack_rate_pps", "t", "existing_trusted_rtt_ms", "packet_in_rate"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(combined_rows)

    fitted = best_fit_series(series)
    trends = rolling_trend_series(series, window=args.smooth_window)
    with fit_csv_output.open("w", newline="") as f:
        fields = [
            "run",
            "configured_attack_rate_pps",
            "avg_existing_trusted_rtt_ms",
            "best_fit_intercept_ms",
            "best_fit_slope_ms_per_sec",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for rate, run_dir, _points, intercept, slope, mean_rtt in fitted:
            writer.writerow({
                "run": run_dir.name,
                "configured_attack_rate_pps": rate,
                "avg_existing_trusted_rtt_ms": round(mean_rtt, 4),
                "best_fit_intercept_ms": round(intercept, 6),
                "best_fit_slope_ms_per_sec": round(slope, 6),
            })

    with trend_csv_output.open("w", newline="") as f:
        fields = ["run", "configured_attack_rate_pps", "t", "rolling_median_rtt_ms"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for rate, run_dir, points in trends:
            for t, rtt in points:
                writer.writerow({
                    "run": run_dir.name,
                    "configured_attack_rate_pps": rate,
                    "t": round(t, 3),
                    "rolling_median_rtt_ms": round(rtt, 4),
                })

    if not _HAS_MPL:
        write_svg(svg_output, series)
        write_rolling_trend_svg(trend_svg_output, trends, args.smooth_window)
        write_best_fit_svg(fit_svg_output, fitted)
        print("[WARN] matplotlib is unavailable; wrote SVG fallback: {}".format(svg_output), file=sys.stderr)
        print(svg_output)
        print(trend_svg_output)
        print(csv_output)
        print(trend_csv_output)
        print(fit_csv_output)
        return

    plt.figure(figsize=(14, 7))
    for rate, _run_dir, points in series:
        xs = [t for t, _ in points]
        ys = [rtt for _, rtt in points]
        matching_pi = [r["packet_in_rate"] for r in combined_rows if r["configured_attack_rate_pps"] == rate and r["packet_in_rate"] != ""]
        if matching_pi:
            label = "{} pps (avg PI {:.1f}/s)".format(rate, sum(matching_pi) / len(matching_pi))
        else:
            label = "{} pps".format(rate)
        plt.plot(xs, ys, linewidth=1.8, label=label)

    plt.xlabel("time (s)")
    plt.ylabel("RTT ms")
    plt.title("Existing trusted-flow RTT across Scapy Packet-In rate sweep")
    plt.grid(True, alpha=0.35)
    if args.max_rtt_ms > 0:
        plt.ylim(bottom=0, top=args.max_rtt_ms)
    plt.legend(title="attack rate", loc="center left", bbox_to_anchor=(1.02, 0.5), borderaxespad=0.0)
    plt.tight_layout(rect=[0, 0, 0.82, 1])
    plt.savefig(output)
    plt.close()

    plt.figure(figsize=(14, 7))
    for rate, _run_dir, points in trends:
        xs = [t for t, _ in points]
        ys = [rtt for _, rtt in points]
        avg_rtt = sum(ys) / len(ys)
        label = "{} pps trend (avg {:.2f} ms)".format(rate, avg_rtt)
        plt.plot(xs, ys, linewidth=2.4, label=label)

    plt.xlabel("time (s)")
    plt.ylabel("rolling median RTT ms")
    plt.title("Rolling median RTT trends for existing trusted flow across rate sweep")
    plt.grid(True, alpha=0.35)
    plt.legend(title="attack rate", loc="center left", bbox_to_anchor=(1.02, 0.5), borderaxespad=0.0)
    plt.tight_layout(rect=[0, 0, 0.78, 1])
    plt.savefig(trend_output)
    plt.close()

    print(output)
    print(trend_output)
    print(csv_output)
    print(trend_csv_output)
    print(fit_csv_output)


if __name__ == "__main__":
    main()
