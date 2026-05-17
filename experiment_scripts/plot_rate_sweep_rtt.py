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


def write_svg(output_path, series, title="Existing trusted-flow RTT across Scapy Packet-In rate sweep", event_times=None):
    width = 1200
    height = 720
    left = 80
    right = 260
    top = 55
    bottom = 70
    plot_w = width - left - right
    plot_h = height - top - bottom

    all_points = [point for _rate, _run_dir, points in series for point in points]
    max_t = max((t for t, _rtt in all_points), default=1.0)
    if event_times:
        max_t = max(max_t, max(event_times.values(), default=max_t))
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

    if event_times:
        marker_legend_y = top + 15
        for idx, name in enumerate(CANONICAL_EVENTS):
            if name not in event_times:
                continue
            style = EVENT_MARKER_STYLES[name]
            x = xscale(event_times[name])
            lines.append('<line x1="{:.2f}" y1="{}" x2="{:.2f}" y2="{}" stroke="{}" stroke-width="2" stroke-dasharray="{}"/>'.format(x, top, x, top + plot_h, style['color'], style['dash']))
            lines.append('<text x="{}" y="{}" font-family="Arial" font-size="12" fill="{}">{}</text>'.format(left + plot_w + 10, marker_legend_y + idx * 18, style['color'], html.escape(name)))

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


def fit_polynomial(points, degree=2):
    if len(points) < degree + 1:
        return None

    xs = [t for t, _rtt in points]
    ys = [rtt for _t, rtt in points]
    order = degree + 1

    A = [[0.0] * order for _ in range(order)]
    b = [0.0] * order
    for x, y in zip(xs, ys):
        powers = [1.0]
        for _ in range(1, 2 * degree + 1):
            powers.append(powers[-1] * x)
        for i in range(order):
            for j in range(order):
                A[i][j] += powers[i + j]
            b[i] += y * powers[i]

    coeffs = _solve_linear_system(A, b)
    return coeffs


def evaluate_polynomial(coeffs, x):
    return sum(coef * (x ** idx) for idx, coef in enumerate(coeffs))

EVENT_NORMALIZATION = {
    'attack_started': 'attack_launched',
    'metering_started': 'metering_started',
    'lockdown_started': 'lockdown_started',
    'escalation_started': 'lockdown_started',
    'mitigation_active': 'lockdown_started',
    'attack_ended': 'attack_ends',
}

EVENT_MARKER_STYLES = {
    'attack_launched': {'color': 'red', 'dash': '4,4'},
    'metering_started': {'color': 'purple', 'dash': '4,4'},
    'lockdown_started': {'color': 'green', 'dash': '4,4'},
    'attack_ends': {'color': 'blue', 'dash': '4,4'},
}

CANONICAL_EVENTS = ['attack_launched', 'metering_started', 'lockdown_started', 'attack_ends']


def event_times(events, names):
    times = {}
    for e in events:
        name = e.get('event')
        if name in names and name not in times:
            times[name] = fnum(e.get('t'))
    return times


def clean_events(events):
    cleaned = []
    for e in events:
        raw_name = e.get('event')
        normalized = EVENT_NORMALIZATION.get(raw_name)
        if normalized is None:
            continue
        t = fnum(e.get('t'), None)
        if t is None:
            continue
        normalized_event = dict(e)
        normalized_event['event'] = normalized
        normalized_event['t'] = t
        cleaned.append(normalized_event)
    return cleaned


def load_events(run_dir):
    path = resolve(run_dir, 'csv', 'events.csv')
    if not path.exists():
        path = run_dir / 'events.csv'
    if not path.exists():
        return []
    return clean_events(read_csv(path))


def combined_event_times(series):
    times = {}
    for _rate, run_dir, _points in series:
        for e in load_events(run_dir):
            name = e['event']
            if name not in times or e['t'] < times[name]:
                times[name] = e['t']
    return times


def draw_transition_markers(ax, event_times):
    drawn = set()
    for name in CANONICAL_EVENTS:
        if name not in event_times:
            continue
        style = EVENT_MARKER_STYLES[name]
        label = name if name not in drawn else None
        ax.axvline(event_times[name], color=style['color'], linestyle='--', linewidth=1.6, alpha=0.75, label=label)
        drawn.add(name)


def polynomial_series(series, degree=2):
    fitted = []
    for rate, run_dir, points in series:
        coeffs = fit_polynomial(points, degree=degree)
        if coeffs is None:
            continue
        min_t = min(t for t, _rtt in points)
        max_t = max(t for t, _rtt in points)
        if max_t == min_t:
            xs = [min_t, min_t + 1.0]
        else:
            xs = [min_t + i * (max_t - min_t) / 100.0 for i in range(101)]
        fitted_points = [(x, evaluate_polynomial(coeffs, x)) for x in xs]
        fitted.append((rate, run_dir, fitted_points))
    return fitted


def write_polynomial_svg(output_path, series, degree, event_times=None):
    title = "Existing trusted-flow RTT degree {} polynomial fit across rate sweep".format(degree)
    write_svg(output_path, series, title=title, event_times=event_times)


def _solve_linear_system(A, b):
    n = len(A)
    if n == 0:
        return None
    M = [row[:] for row in A]
    v = b[:]
    for i in range(n):
        pivot = i
        for j in range(i + 1, n):
            if abs(M[j][i]) > abs(M[pivot][i]):
                pivot = j
        if abs(M[pivot][i]) < 1e-12:
            return None
        M[i], M[pivot] = M[pivot], M[i]
        v[i], v[pivot] = v[pivot], v[i]
        pivot_val = M[i][i]
        for j in range(i, n):
            M[i][j] /= pivot_val
        v[i] /= pivot_val
        for k in range(n):
            if k == i:
                continue
            factor = M[k][i]
            for j in range(i, n):
                M[k][j] -= factor * M[i][j]
            v[k] -= factor * v[i]
    return v


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
    degree_outputs = {
        1: output.with_name(output.stem + "_degree1" + output.suffix),
        2: output.with_name(output.stem + "_degree2" + output.suffix),
        3: output.with_name(output.stem + "_degree3" + output.suffix),
        4: output.with_name(output.stem + "_degree4" + output.suffix),
        6: output.with_name(output.stem + "_degree6" + output.suffix),
        40: output.with_name(output.stem + "_degree40" + output.suffix),
        50: output.with_name(output.stem + "_degree50" + output.suffix),
        60: output.with_name(output.stem + "_degree60" + output.suffix),
        70: output.with_name(output.stem + "_degree70" + output.suffix),
        80: output.with_name(output.stem + "_degree80" + output.suffix),
    }
    degree_svg_outputs = {degree: path.with_suffix(".svg") for degree, path in degree_outputs.items()}
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

    event_times_all = combined_event_times(series)

    if not _HAS_MPL:
        write_svg(svg_output, series, event_times=event_times_all)
        for degree, path in degree_svg_outputs.items():
            write_polynomial_svg(path, polynomial_series(series, degree), degree, event_times=event_times_all)
        print("[WARN] matplotlib is unavailable; wrote SVG fallback: {}".format(svg_output), file=sys.stderr)
        print(svg_output)
        for degree in sorted(degree_svg_outputs):
            print(degree_svg_outputs[degree])
        print(csv_output)
        return

    def plot_series(output_path, title, pairs, event_times):
        plt.figure(figsize=(14, 7))
        for rate, _run_dir, points in pairs:
            xs = [t for t, _ in points]
            ys = [rtt for _, rtt in points]
            label = "{} pps".format(rate)
            plt.plot(xs, ys, linewidth=1.8, label=label)
        draw_transition_markers(plt.gca(), event_times)
        plt.xlabel("time (s)")
        plt.ylabel("RTT ms")
        plt.title(title)
        plt.grid(True, alpha=0.35)
        if args.max_rtt_ms > 0:
            plt.ylim(bottom=0, top=args.max_rtt_ms)
        plt.legend(title="attack rate", loc="center left", bbox_to_anchor=(1.02, 0.5), borderaxespad=0.0)
        plt.tight_layout(rect=[0, 0, 0.82, 1])
        plt.savefig(output_path)
        plt.close()

    plot_series(output, "Existing trusted-flow RTT across Scapy Packet-In rate sweep", series, event_times_all)
    for degree in (1, 2, 3, 4, 6, 40, 50, 60, 70, 80):
        plot_series(
            degree_outputs[degree],
            "Existing trusted-flow RTT degree {} polynomial fit across rate sweep".format(degree),
            polynomial_series(series, degree),
            event_times_all,
        )

    print(output)
    for degree in sorted(degree_outputs):
        print(degree_outputs[degree])
    print(csv_output)


if __name__ == "__main__":
    main()
