#!/usr/bin/env python3
import argparse, csv, os, math, sys
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    _HAS_MPL = True
except ImportError:
    plt = None
    _HAS_MPL = False

def read_csv(path):
    if not os.path.exists(path): return []
    with open(path, newline='') as f: return list(csv.DictReader(f))

def num(row, key, default=0.0):
    try: return float(row.get(key, default) or default)
    except Exception: return default

def boolish(v):
    return str(v).lower() in ('true','1','yes','on')

def event_times(events, names):
    times = {}
    for e in events:
        name = e.get("event")
        if name in names and name not in times:
            times[name] = num(e, "t")
    return times

EVENT_NORMALIZATION = {
    'attack_started': 'attack_launched',
    'metering_started': 'metering_started',
    'lockdown_started': 'lockdown_started',
    'escalation_started': 'lockdown_started',
    'mitigation_active': 'lockdown_started',
    'attack_ended': 'attack_ends',
}

KNOWN_EVENTS = set(EVENT_NORMALIZATION.keys())
CANONICAL_EVENTS = ['attack_launched', 'metering_started', 'lockdown_started', 'attack_ends']
EVENT_STYLES = {
    'attack_launched': {'color': 'red', 'label': 'attack_launched'},
    'metering_started': {'color': 'purple', 'label': 'metering_started'},
    'lockdown_started': {'color': 'green', 'label': 'lockdown_started'},
    'attack_ends': {'color': 'blue', 'label': 'attack_ends'},
}

def clean_events(events):
    cleaned = []
    for e in events:
        raw_name = e.get('event')
        normalized = EVENT_NORMALIZATION.get(raw_name)
        if normalized is None:
            continue
        try:
            float(e.get('t', ''))
        except Exception:
            continue
        normalized_event = dict(e)
        normalized_event['event'] = normalized
        cleaned.append(normalized_event)
    return cleaned


def add_transition_markers(ax, events, fallback=None):
    drawn = set()
    marker_handles = []
    for name in CANONICAL_EVENTS:
        style = EVENT_STYLES[name]
        for e in events:
            if e.get('event') != name:
                continue
            line = ax.axvline(num(e, 't'), color=style['color'], linestyle='--', linewidth=1.5, alpha=0.85, label=name)
            marker_handles.append((line, name))
            drawn.add(name)
            break
    if fallback:
        for name, fallback_time in fallback.items():
            if name in drawn or fallback_time is None:
                continue
            style = EVENT_STYLES.get(name)
            if not style:
                continue
            line = ax.axvline(fallback_time, color=style['color'], linestyle='--', linewidth=1.5, alpha=0.85, label=name)
            marker_handles.append((line, name))
            drawn.add(name)
    return marker_handles


def place_legend(outside=False):
    """Place the main legend for plot data and a separate legend for transition markers."""
    ax = plt.gca()
    handles, labels = ax.get_legend_handles_labels()
    if not handles:
        return

    data_handles = []
    data_labels = []
    marker_handles = []
    marker_labels = []
    for handle, label in zip(handles, labels):
        if label in CANONICAL_EVENTS:
            marker_handles.append(handle)
            marker_labels.append(label)
        else:
            data_handles.append(handle)
            data_labels.append(label)

    if data_handles:
        data_handles, data_labels = _sort_legend_handles_labels(data_handles, data_labels)
        loc = _choose_legend_location(ax)
        data_legend = ax.legend(data_handles, data_labels, loc=loc, framealpha=0.85, edgecolor='black', fancybox=True)
        ax.add_artist(data_legend)

    if marker_handles:
        marker_loc = 'upper left' if not outside else 'center left'
        legend_kwargs = {
            'loc': marker_loc,
            'title': 'events',
            'framealpha': 0.85,
            'edgecolor': 'black',
            'fancybox': True,
        }
        if outside:
            legend_kwargs['bbox_to_anchor'] = (1.02, 0.5)
        ax.legend(marker_handles, marker_labels, **legend_kwargs)

    plt.tight_layout()


def _sort_legend_handles_labels(handles, labels):
    ordered = []
    others = []
    for idx, (handle, label) in enumerate(zip(handles, labels)):
        xdata = None
        if hasattr(handle, 'get_xdata'):
            try:
                xdata = handle.get_xdata()
            except Exception:
                xdata = None
        is_vertical = False
        if xdata is not None and len(xdata) >= 2:
            try:
                is_vertical = all(abs(float(x) - float(xdata[0])) < 1e-9 for x in xdata)
            except Exception:
                is_vertical = False
        if is_vertical:
            ordered.append((float(xdata[0]), idx, handle, label))
        else:
            others.append((idx, handle, label))

    others.sort(key=lambda item: item[0])
    ordered.sort(key=lambda item: item[0])
    sorted_handles = [handle for _idx, handle, _label in others] + [handle for _x, _idx, handle, _label in ordered]
    sorted_labels = [label for _idx, _handle, label in others] + [label for _x, _idx, _handle, label in ordered]
    return sorted_handles, sorted_labels


def _choose_legend_location(ax):
    candidates = ['upper right', 'upper left', 'lower right', 'lower left']
    x0, x1 = ax.get_xlim()
    y0, y1 = ax.get_ylim()
    if x0 == x1 or y0 == y1:
        return 'upper right'

    points = []
    for line in ax.get_lines():
        xs = line.get_xdata()
        ys = line.get_ydata()
        points.extend(zip(xs, ys))

    if not points:
        return 'upper right'

    best_loc = None
    best_score = None
    for loc in candidates:
        score = _legend_overlap_score(points, x0, x1, y0, y1, loc)
        if best_score is None or score < best_score:
            best_score = score
            best_loc = loc
    return best_loc or 'upper right'


def _legend_overlap_score(points, x0, x1, y0, y1, loc):
    x_span = x1 - x0
    y_span = y1 - y0
    x_frac = 0.30
    y_frac = 0.25

    if 'left' in loc:
        x_min = x0
        x_max = x0 + x_span * x_frac
    else:
        x_min = x1 - x_span * x_frac
        x_max = x1

    if 'lower' in loc:
        y_min = y0
        y_max = y0 + y_span * y_frac
    else:
        y_min = y1 - y_span * y_frac
        y_max = y1

    score = 0
    for x, y in points:
        if x_min <= x <= x_max and y_min <= y <= y_max:
            score += 1
            if score > 100:
                break
    return score

def _csv(d, name):
    """Resolve a CSV/JSON data file: prefer csv/ subdir (post-run), fall back to root."""
    sub = os.path.join(d, 'csv', name)
    return sub if os.path.exists(sub) else os.path.join(d, name)

def _log(d, name):
    """Resolve a log file: prefer logs/ subdir (post-run), fall back to root."""
    sub = os.path.join(d, 'logs', name)
    return sub if os.path.exists(sub) else os.path.join(d, name)

def _csv_write(d, name):
    """Path for a derived CSV to write; always places it in csv/ subdir."""
    csv_dir = os.path.join(d, 'csv')
    os.makedirs(csv_dir, exist_ok=True)
    return os.path.join(csv_dir, name)

def save_line(rows, x, ys, labels, title, ylabel, out):
    if not rows: return False
    plt.figure()
    xs=[num(r,x) for r in rows]
    all_vals=[]
    for y,l in zip(ys,labels):
        yvals=[num(r,y) for r in rows]
        plt.plot(xs, yvals, label=l)
        all_vals.extend(yvals)
    plt.xlabel('time (seconds)' if x=='t' else x); plt.ylabel(ylabel); plt.title(title)
    _smart_ylim(all_vals)
    plt.grid(True)
    place_legend()
    plt.savefig(out)
    plt.close()
    return True


def _percentile99(values):
    """99th-percentile of a list of floats, ignoring None/zero."""
    vals = sorted(v for v in values if v is not None and v > 0)
    if not vals:
        return None
    return vals[min(int(len(vals) * 0.99), len(vals) - 1)]


def _smart_ylim(values, margin=0.15):
    """Clip the y-axis upper bound to the 99th percentile plus headroom.
    Prevents a single initial spike from compressing the rest of the chart."""
    cap = _percentile99(values)
    if cap is not None and cap > 0:
        plt.ylim(bottom=0, top=cap * (1 + margin))


def rows_between(rows, start, end=None):
    out = []
    for row in rows:
        t = num(row, 't')
        if t < start:
            continue
        if end is not None and t > end:
            continue
        out.append(row)
    return out


def average(values):
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def pct_reduction(before, after):
    if before is None or after is None or before <= 0:
        return None
    return ((before - after) / before) * 100.0


def write_lockdown_summary(run_dir, events, status_plot, link_plot, mit_plot):
    ev_times = event_times(events, ['metering_started', 'lockdown_started', 'attack_ends'])
    metering_start = ev_times.get('metering_started') or ev_times.get('lockdown_started')
    escalation_start = ev_times.get('lockdown_started')
    attack_end = ev_times.get('attack_ends')
    if metering_start is None or escalation_start is None:
        return None

    # Skip the first few seconds after escalation so 3s Packet-In windows and
    # interface deltas have time to reflect the drop rule.
    post_start = escalation_start + 3.0
    pre_status = rows_between(status_plot, metering_start, escalation_start)
    post_status = rows_between(status_plot, post_start, attack_end)
    pre_link = rows_between(link_plot, metering_start, escalation_start)
    post_link = rows_between(link_plot, post_start, attack_end)
    pre_mit = rows_between(mit_plot, metering_start, escalation_start)
    post_mit = rows_between(mit_plot, post_start, attack_end)

    pre_packetin = average([num(r, 'packet_in_rate') for r in pre_status])
    post_packetin = average([num(r, 'packet_in_rate') for r in post_status])
    pre_pps = average([num(r, 'total_pps') for r in pre_link])
    post_pps = average([num(r, 'total_pps') for r in post_link])
    post_escalated = average([num(r, 'escalated_ports_count') for r in post_mit])

    summary = {
        'metering_start': metering_start,
        'escalation_start': escalation_start,
        'post_lockdown_start': post_start,
        'attack_end': attack_end if attack_end is not None else '',
        'metering_avg_packet_in_rate': pre_packetin,
        'lockdown_avg_packet_in_rate': post_packetin,
        'packet_in_rate_reduction_pct': pct_reduction(pre_packetin, post_packetin),
        'metering_avg_total_pps': pre_pps,
        'lockdown_avg_total_pps': post_pps,
        'total_pps_reduction_pct': pct_reduction(pre_pps, post_pps),
        'lockdown_avg_escalated_ports': post_escalated,
    }

    path = _csv_write(run_dir, 'lockdown_impact_summary.csv')
    with open(path, 'w', newline='') as f:
        fields = list(summary.keys())
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerow({k: '' if v is None else round(v, 4) if isinstance(v, float) else v for k, v in summary.items()})
    return summary


def _solve_linear_system(A, b):
    n = len(b)
    M = [row[:] for row in A]
    y = b[:]

    for i in range(n):
        pivot = i
        for j in range(i + 1, n):
            if abs(M[j][i]) > abs(M[pivot][i]):
                pivot = j
        if abs(M[pivot][i]) < 1e-12:
            return None
        if pivot != i:
            M[i], M[pivot] = M[pivot], M[i]
            y[i], y[pivot] = y[pivot], y[i]

        diag = M[i][i]
        M[i] = [mij / diag for mij in M[i]]
        y[i] /= diag

        for j in range(n):
            if j == i:
                continue
            factor = M[j][i]
            if factor:
                M[j] = [m_j - factor * m_i for m_j, m_i in zip(M[j], M[i])]
                y[j] -= factor * y[i]

    return y

def main():
    p=argparse.ArgumentParser()
    p.add_argument('input_dir')
    p.add_argument('--output', default='')
    p.add_argument('--trim-start', type=float, default=5.0,
                   help='Exclude the first N seconds from all time-series plots '
                        'to remove the topology-learning burst at t=0 (default: 5)')
    a=p.parse_args(); d=a.input_dir
    out=a.output or os.path.join(d,'plots')
    os.makedirs(out, exist_ok=True)
    trim = a.trim_start

    metrics=read_csv(_csv(d,'controller_metrics.csv'))
    status=read_csv(_csv(d,'attack_status.csv'))
    mit=read_csv(_csv(d,'mitigation_metrics.csv'))
    link=read_csv(_csv(d,'controller_link_util.csv'))
    events=clean_events(read_csv(_csv(d,'events.csv')))

    def trim_rows(rows):
        """Drop rows before trim_start so the initial spike is excluded from plots."""
        return [r for r in rows if num(r, 't') >= trim]

    status_plot  = trim_rows(status)
    metrics_plot = trim_rows(metrics)
    mit_plot     = trim_rows(mit)
    link_plot    = trim_rows(link)

    made=[]
    if not _HAS_MPL:
        if status_plot and mit_plot:
            write_lockdown_summary(d, events, status_plot, link_plot, mit_plot)
        print('[WARN] matplotlib not available; wrote derived CSVs only', flush=True)
        return
    
    if status_plot:
        plt.figure(figsize=(14, 6))
        xs=[num(r,'t') for r in status_plot]
        ys=[num(r,'packet_in_rate') for r in status_plot]
        plt.plot(xs,ys,label='Packet-In rate')
        thr=[num(r,'threshold_rate') for r in status_plot if r.get('threshold_rate') not in ('',None)]
        ax = plt.gca()
        if thr:
            try:
                thr_val = float(thr[0])
                ax.axhline(thr_val, color='black', linestyle=':', linewidth=1.6, label='Threshold')
            except Exception:
                pass
        add_transition_markers(ax, events)

        mitigation_inactive_time = None
        for i in range(len(status_plot)-1):
            curr_active = boolish(status_plot[i].get('mitigation_active', False))
            next_active = boolish(status_plot[i+1].get('mitigation_active', False))
            if curr_active and not next_active:
                mitigation_inactive_time = num(status_plot[i+1], 't')
                break
        if mitigation_inactive_time:
            plt.axvline(mitigation_inactive_time, color='purple', label='mitigation_inactive')

        _smart_ylim(ys)
        plt.xlabel('time (seconds)'); plt.ylabel('Packet-In events/sec')
        plt.title('Attack detection: Packet-In rate over time')
        plt.grid(True)
        place_legend(outside=True)
        path=os.path.join(out,'packetin_rate_detection.png'); plt.savefig(path); plt.close(); made.append(path)
    
    if metrics_plot:
        plt.figure(figsize=(14, 6))
        xs = [num(r, 't') for r in metrics_plot]
        ys = [num(r, 'controller_cpu_percent') for r in metrics_plot]

        plt.plot(xs, ys, label='CPU %')
        ax = plt.gca()
        add_transition_markers(ax, events)

        mitigation_inactive_time = None
        if status_plot:
            for i in range(len(status_plot)-1):
                curr_active = boolish(status_plot[i].get('mitigation_active', False))
                next_active = boolish(status_plot[i+1].get('mitigation_active', False))
                if curr_active and not next_active:
                    mitigation_inactive_time = num(status_plot[i+1], 't')
                    break
        if mitigation_inactive_time:
            plt.axvline(mitigation_inactive_time, color='purple', label='mitigation_inactive')

        _smart_ylim(ys)
        plt.xlabel('time (seconds)')
        plt.ylabel('CPU %')
        plt.title('Controller CPU over time')
        plt.grid(True)
        place_legend(outside=True)

        path = os.path.join(out, 'cpu_over_time.png')
        plt.savefig(path)
        plt.close()
        made.append(path)
    
    if mit_plot:
        plt.figure(figsize=(14, 6))
        xs = [num(r, 't') for r in mit_plot]

        mitigated_rates = [0]
        unknown_rates = [0]
        overrate_rates = [0]

        for i in range(1, len(mit_plot)):
            dt = xs[i] - xs[i-1]
            if dt > 0:
                mitigated_rates.append((num(mit_plot[i], 'mitigated_drop_count') - num(mit_plot[i-1], 'mitigated_drop_count')) / dt)
                unknown_rates.append((num(mit_plot[i], 'dropped_unknown_count') - num(mit_plot[i-1], 'dropped_unknown_count')) / dt)
                overrate_rates.append((num(mit_plot[i], 'dropped_overrate_count') - num(mit_plot[i-1], 'dropped_overrate_count')) / dt)
            else:
                mitigated_rates.append(0)
                unknown_rates.append(0)
                overrate_rates.append(0)

        plt.plot(xs, mitigated_rates, label='total drops/sec')
        plt.plot(xs, unknown_rates, label='unknown source drops/sec')
        plt.plot(xs, overrate_rates, label='over-rate drops/sec')

        ax = plt.gca()
        add_transition_markers(ax, events)
        _smart_ylim(mitigated_rates + unknown_rates + overrate_rates)
        plt.xlabel('time (seconds)')
        plt.ylabel('drops/sec')
        plt.title('Mitigation drops rate over time')
        plt.grid(True)
        place_legend()
        path = os.path.join(out, 'mitigation_drops_over_time.png')
        plt.savefig(path)
        plt.close()
        made.append(path)
    
    if mit:
        last = mit[-1]

        vals = [
            num(last, 'dropped_unknown_count'),
            num(last, 'dropped_overrate_count'),
            num(last, 'trusted_source_count'),
            num(last, 'mitigated_source_count')
        ]

        labs = [
            'unknown drops',
            'over-rate drops',
            'trusted sources',
            'mitigated sources'
        ]

        plt.figure(figsize=(14, 6))
        bars = plt.bar(labs, vals)

        # Print the count above each bar
        for bar, value in zip(bars, vals):
            plt.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                str(int(value)),
                ha='center',
                va='bottom'
            )

        plt.ylabel('count')
        plt.title('Mitigation effectiveness summary')
        plt.xticks(rotation=20, ha='right')
        plt.tight_layout()

        path = os.path.join(out, 'mitigation_effectiveness_bar.png')
        plt.savefig(path)
        plt.close()
        made.append(path)
    
    lutil_png=os.path.join(out,'controller_link_util_over_time.png')
    if link_plot:
        plt.figure(figsize=(14, 6))
        xs=[num(r,'t') for r in link_plot]
        has_pps = any((r.get('total_pps') not in ('', None) for r in link_plot))
        all_vals=[]

        if has_pps:
            total=[num(r,'total_pps') for r in link_plot]
            rx=[num(r,'rx_pps') for r in link_plot]
            tx=[num(r,'tx_pps') for r in link_plot]
            plt.plot(xs,total,label='total pps')
            plt.plot(xs,rx,label='rx pps')
            plt.plot(xs,tx,label='tx pps')
            all_vals.extend(total + rx + tx)
            ylabel='packet per second'
            title='Controller link packet rate over time'
        else:
            total=[num(r,'total_mbps') for r in link_plot]
            rx=[num(r,'rx_mbps') for r in link_plot]
            tx=[num(r,'tx_mbps') for r in link_plot]
            plt.plot(xs,total,label='total Mbps')
            plt.plot(xs,rx,label='rx Mbps')
            plt.plot(xs,tx,label='tx Mbps')
            all_vals.extend(total + rx + tx)
            ylabel='Mbits per second'
            title='Controller link utilization over time (legacy)'

        ax = plt.gca()
        add_transition_markers(ax, events)
        _smart_ylim(all_vals)
        plt.xlabel('time (seconds)')
        plt.ylabel(ylabel)
        plt.title(title)
        plt.grid(True)
        place_legend(outside=True)
        plt.savefig(lutil_png)
        plt.close()
        made.append(lutil_png)

    if status_plot and mit_plot:
        summary = write_lockdown_summary(d, events, status_plot, link_plot, mit_plot)
        ev_times = event_times(events, ['metering_started', 'lockdown_started', 'attack_ends'])
        metering_start = ev_times.get('metering_started') or ev_times.get('lockdown_started')
        escalation_start = ev_times.get('lockdown_started')
        if metering_start is not None and escalation_start is not None:
            fig, axes = plt.subplots(3, 1, figsize=(14, 10), sharex=True)

            status_x = [num(r, 't') for r in status_plot]
            packet_in = [num(r, 'packet_in_rate') for r in status_plot]
            axes[0].plot(status_x, packet_in, color='tab:red', label='Packet-In rate')
            axes[0].set_ylabel('Packet-In/s')
            axes[0].set_title('Lockdown impact: controller pressure before and after escalation')
            axes[0].grid(True, alpha=0.35)

            # draw threshold on Packet-In axis if present
            thr = [num(r,'threshold_rate') for r in status_plot if r.get('threshold_rate') not in ('',None)]
            if thr:
                try:
                    axes[0].axhline(float(thr[0]), color='black', linestyle=':', linewidth=1.6, label='Threshold')
                except Exception:
                    pass

            if link_plot:
                link_x = [num(r, 't') for r in link_plot]
                link_total = [num(r, 'total_pps') for r in link_plot]
                axes[1].plot(link_x, link_total, color='tab:blue', label='controller-link total pps')
            else:
                axes[1].text(0.5, 0.5, 'controller_link_util.csv unavailable', ha='center', va='center', transform=axes[1].transAxes)
            axes[1].set_ylabel('link pps')
            axes[1].grid(True, alpha=0.35)

            mit_x = [num(r, 't') for r in mit_plot]
            rate_limited = [num(r, 'rate_limited_ports_count') for r in mit_plot]
            escalated = [num(r, 'escalated_ports_count') for r in mit_plot]
            axes[2].step(mit_x, rate_limited, where='post', label='rate-limited ports', color='tab:purple')
            axes[2].step(mit_x, escalated, where='post', label='lockdown/drop ports', color='tab:brown')
            axes[2].set_ylabel('ports')
            axes[2].set_xlabel('time (seconds)')
            axes[2].grid(True, alpha=0.35)

            attack_end = ev_times.get('attack_ends')
            window_end = attack_end if attack_end is not None else max(status_x or mit_x)
            for ax in axes:
                add_transition_markers(ax, events)
                ax.axvspan(metering_start, escalation_start, color='tab:purple', alpha=0.08, label='metering window')
                ax.axvspan(escalation_start, window_end, color='tab:brown', alpha=0.10, label='lockdown window')

            if summary:
                pir_drop = summary.get('packet_in_rate_reduction_pct')
                pps_drop = summary.get('total_pps_reduction_pct')
                notes = []
                if pir_drop is not None:
                    notes.append('Packet-In avg reduction: {:.1f}%'.format(pir_drop))
                if pps_drop is not None:
                    notes.append('Link PPS avg reduction: {:.1f}%'.format(pps_drop))
                if notes:
                    axes[0].text(
                        0.01, 0.95, '\n'.join(notes),
                        transform=axes[0].transAxes,
                        va='top',
                        bbox={'boxstyle': 'round,pad=0.35', 'facecolor': 'white', 'alpha': 0.85, 'edgecolor': '#cccccc'}
                    )

            for ax in axes:
                plt.sca(ax)
                place_legend()

            plt.tight_layout()
            path = os.path.join(out, 'lockdown_impact_summary.png')
            plt.savefig(path)
            plt.close()
            made.append(path)
    # parse ping RTT logs — one combined plot covering both existing and new legitimate traffic flows
    import json, re

    config_path = os.path.join(d, 'config.json')
    attack_delay = 0
    valid_new_delay = 10
    ping_interval = 0.5

    if os.path.exists(config_path):
        with open(config_path) as cf:
            cfg = json.load(cf)
            attack_delay = float(cfg.get('attack_delay', 0) or 0)
            valid_new_delay = float(cfg.get('valid_new_delay', 10) or 10)

    plt.figure(figsize=(14, 6))
    has_ping = False
    ping_series = []

    for name, offset in [('ping_existing', 0), ('ping_new', valid_new_delay)]:
        log = _log(d, '{}.log'.format(name))
        rows = []

        if os.path.exists(log):
            idx = 0
            with open(log, errors='ignore') as f:
                for line in f:
                    m = re.search(r'time=([0-9.]+)\s*ms', line)
                    if m:
                        rows.append({
                            't': offset + idx * ping_interval,
                            'rtt_ms': float(m.group(1))
                        })
                        idx += 1

        if rows:
            has_ping = True
            csvp = _csv_write(d, '{}.csv'.format(name))
            with open(csvp, 'w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=['t', 'rtt_ms'])
                w.writeheader()
                w.writerows(rows)

            # Trim the warm-up window from the plot (CSV keeps full data).
            rows_plot = [r for r in rows if r['t'] >= trim]
            label = 'existing trusted flow' if name == 'ping_existing' else 'new trusted flow'
            color = 'tab:blue' if name == 'ping_existing' else 'tab:orange'
            plt.plot([r['t'] for r in rows_plot], [r['rtt_ms'] for r in rows_plot], label=label, color=color)
            ping_series.append((label, rows_plot, color))

    if has_ping:
        ax = plt.gca()
        add_transition_markers(ax, events, fallback={'attack_launched': attack_delay})

        mitigation_inactive_time = None
        if status_plot:
            for i in range(len(status_plot)-1):
                curr_active = boolish(status_plot[i].get('mitigation_active', False))
                next_active = boolish(status_plot[i+1].get('mitigation_active', False))
                if curr_active and not next_active:
                    mitigation_inactive_time = num(status_plot[i+1], 't')
                    break
        if mitigation_inactive_time is not None:
            plt.axvline(mitigation_inactive_time, color='purple', label='mitigation_inactive')

        ax = plt.gca()
        rtt_flat = [v for line in ax.get_lines() for v in line.get_ydata()]
        _smart_ylim(rtt_flat)
        plt.xlabel('time (seconds)')
        plt.ylabel('RTT ms')
        plt.title('Legitimate Traffic RTT During Attack and Recovery')
        plt.grid(True)
        place_legend()

        fig = plt.gcf()
        fig.set_size_inches(14, 6)
        plt.tight_layout()

        path = os.path.join(out, 'legitimate_rtt_combined_raw.png')
        plt.savefig(path)
        plt.close()
        made.append(path)
    else:
        plt.close()
    

    # parse iperf throughput logs for trusted traffic
    import re
    def parse_iperf_log(path, offset=0.0):
        rows = []
        if not os.path.exists(path):
            return rows
        idx = 0
        with open(path, errors='ignore') as f:
            for line in f:
                if 'bits/sec' not in line:
                    continue
                m = re.search(r'([0-9.]+)\s+([KMG])?bits/sec', line)
                if not m:
                    continue
                val = float(m.group(1))
                unit = m.group(2) or ''
                if unit == 'K':
                    val = val / 1000.0
                elif unit == 'G':
                    val = val * 1000.0
                rows.append({'t': offset + idx, 'mbps': val})
                idx += 1
        return rows

    config_path = os.path.join(d, 'config.json')
    valid_new_delay = 10
    attack_delay = 0
    if os.path.exists(config_path):
        with open(config_path) as cf:
            cfg = json.load(cf)
            valid_new_delay = float(cfg.get('valid_new_delay', 10) or 10)
            attack_delay = float(cfg.get('attack_delay', 0) or 0)

    iperf_series = [
        ('iperf_existing', 'existing trusted throughput', 0),
        ('iperf_new', 'new trusted throughput', valid_new_delay),
    ]
    plt.figure(figsize=(14, 6))
    has_iperf = False
    for log_name, label, offset in iperf_series:
        rows = parse_iperf_log(_log(d, '{}.log'.format(log_name)), offset)
        if not rows:
            continue
        has_iperf = True
        csvp = _csv_write(d, '{}.csv'.format(log_name))
        with open(csvp, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['t', 'mbps'])
            w.writeheader()
            w.writerows(rows)
        rows_plot = [r for r in rows if r['t'] >= trim]
        plt.plot([r['t'] for r in rows_plot], [r['mbps'] for r in rows_plot], label=label)

    if has_iperf:
        ax = plt.gca()
        add_transition_markers(ax, events, fallback={'attack_launched': attack_delay})
        iperf_flat = [v for line in ax.get_lines() for v in line.get_ydata()]
        _smart_ylim(iperf_flat)
        plt.xlabel('time (seconds)')
        plt.ylabel('Mbits per second')
        plt.title('Trusted Throughput During Attack and Recovery')
        plt.grid(True)
        place_legend()
        path = os.path.join(out, 'trusted_throughput_combined.png')
        plt.savefig(path)
        plt.close()
        made.append(path)
    else:
        plt.close()
    
    if mit_plot:
        plt.figure(figsize=(14, 6))
        xs=[num(r,'t') for r in mit_plot]
        rate_limited=[num(r,'rate_limited_ports_count') for r in mit_plot]
        escalated=[num(r,'escalated_ports_count') for r in mit_plot]
        
        plt.plot(xs, rate_limited, label='rate-limited ports', marker='o')
        plt.plot(xs, escalated, label='escalated (drop) ports', marker='s')
        
        ax = plt.gca()
        add_transition_markers(ax, events)
        
        plt.xlabel('time (seconds)')
        plt.ylabel('number of ports')
        plt.title('Port-level mitigation escalation over time')
        plt.grid(True)
        place_legend()
        path=os.path.join(out,'mitigation_port_escalation.png')
        plt.savefig(path)
        plt.close()
        made.append(path)

    if events:
        order=['attack_launched','metering_started','lockdown_started','attack_ends']
        evs=[e for e in events if e.get('event') in order]
        if evs:
            plt.figure(figsize=(10, 6))
            plt.scatter([num(e,'t') for e in evs],[order.index(e.get('event')) for e in evs], s=100)
            plt.yticks(range(len(order)), order)
            plt.xlabel('time (seconds)')
            plt.title('Attack launch and mitigation response timeline')
            plt.grid(True, alpha=0.3)
            # Set y-axis limits with padding to zoom in on the metrics
            plt.ylim(-0.5, len(order) - 0.5)
            plt.tight_layout()
            path=os.path.join(out,'response_timeline.png')
            plt.savefig(path)
            plt.close()
            made.append(path)
    with open(os.path.join(out,'graphs_created.txt'),'w') as f:
        for pth in made: f.write(pth+'\n')
    print('\n'.join(made))
if __name__=='__main__': main()
