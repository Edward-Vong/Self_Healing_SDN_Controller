#!/usr/bin/env python3
import argparse, csv, json, math, os, time, urllib.request, urllib.error, subprocess, re, threading

def get_json(base, path):
    url = base.rstrip('/') + path
    with urllib.request.urlopen(url, timeout=2) as r:
        return json.loads(r.read().decode('utf-8'))

def read_iface_stats(iface):
    """Read byte, drop, and error counters from sysfs for the given interface.
    Returns a dict or None if unavailable."""
    if not iface:
        return None
    base = '/sys/class/net/{}/statistics'.format(iface)
    fields = (
        'rx_bytes', 'tx_bytes',
        'rx_packets', 'tx_packets',
        'rx_dropped', 'tx_dropped',
        'rx_errors', 'tx_errors'
    )
    result = {}
    try:
        for field in fields:
            with open(os.path.join(base, field)) as f:
                result[field] = int(f.read().strip())
        return result
    except Exception:
        return None


def read_iface_bytes(iface):
    stats = read_iface_stats(iface)
    if stats is None:
        return None
    return stats['rx_bytes'], stats['tx_bytes']

def flat_mitigation(m):
    mit = m.get('mitigation', {}) if isinstance(m, dict) else {}
    rate_limited = []
    escalated = []
    for dpid, ports in (mit.get('rate_limited_ports') or {}).items():
        rate_limited.extend(ports)
    for dpid, ports in (mit.get('escalated_ports') or {}).items():
        escalated.extend(ports)
    return {
        'phase': m.get('phase', mit.get('phase', '')),
        'lockdown_active': bool(mit.get('lockdown_active', False)),
        'mitigated_drop_count': mit.get('mitigated_drop_count', 0),
        'dropped_unknown_count': mit.get('dropped_unknown_count', 0),
        'dropped_overrate_count': mit.get('dropped_overrate_count', 0),
        'dropped_unknown_destination_count': mit.get('dropped_unknown_destination_count', 0),
        'trusted_source_count': len(mit.get('trusted_sources', [])),
        'source_seen_count_total': sum((mit.get('source_seen_counts') or {}).values()),
        'mitigated_source_count': len(mit.get('mitigated_sources', {})),
        'rate_limited_ports_count': len(rate_limited),
        'escalated_ports_count': len(escalated),
    }

def compute_stats(values):
    if not values:
        return {"mean": None, "min": None, "max": None, "stddev": None, "count": 0}
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return {
        "mean": round(mean, 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "stddev": round(math.sqrt(variance), 4),
        "count": n,
    }

def wait_for_controller(base, timeout=30, interval=1.0):
    """Block until the controller /stats endpoint responds or timeout expires.
    Returns True if reachable, False if timed out."""
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        try:
            get_json(base, '/stats')
            if attempt > 0:
                print("Controller reachable after {}s".format(round(time.time() - (deadline - timeout), 1)))
            return True
        except Exception:
            attempt += 1
            time.sleep(interval)
    print("[WARN] Controller not reachable after {}s; starting collection anyway".format(timeout))
    return False


class SwitchRTTProber(threading.Thread):
    """Background thread that pings a list of IPs every `interval` seconds
    and writes RTT samples to switch_rtt.csv."""

    def __init__(self, ips, out_dir, start_time, interval=5.0):
        super().__init__(daemon=True)
        self.ips = [ip.strip() for ip in ips if ip.strip()]
        self.out_dir = out_dir
        self.start_time = start_time
        self.interval = interval
        self._stop_event = threading.Event()
        self.csv_path = os.path.join(out_dir, 'switch_rtt.csv')

    def stop(self):
        self._stop_event.set()

    LOSS_WINDOW = 10       # rolling window size for loss rate
    SATURATED_LOSS_PCT = 50.0  # loss % threshold to emit node_saturated event

    def _ping_once(self, ip):
        """Run a single ping and return RTT in ms, or None on failure."""
        try:
            out = subprocess.check_output(
                ['ping', '-c', '1', '-W', '2', ip],
                stderr=subprocess.DEVNULL, timeout=4
            ).decode('utf-8', errors='replace')
            m = re.search(r'time[=<]([\d.]+)\s*ms', out)
            if m:
                return float(m.group(1))
        except Exception:
            pass
        return None

    def run(self):
        os.makedirs(self.out_dir, exist_ok=True)
        # Per-IP rolling history: list of 1 (reachable) or 0 (dropped)
        history = {ip: [] for ip in self.ips}
        # Track whether each IP is currently in a saturated state for edge events
        saturated = {ip: False for ip in self.ips}
        events_path = os.path.join(self.out_dir, 'events.csv')
        with open(self.csv_path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['t', 'timestamp', 'ip', 'rtt_ms', 'reachable', 'loss_pct_last10'])
            w.writeheader()
            while not self._stop_event.is_set():
                now = time.time()
                t = round(now - self.start_time, 3)
                for ip in self.ips:
                    rtt = self._ping_once(ip)
                    reachable = 1 if rtt is not None else 0
                    hist = history[ip]
                    hist.append(reachable)
                    if len(hist) > self.LOSS_WINDOW:
                        hist.pop(0)
                    loss_pct = round((1 - sum(hist) / len(hist)) * 100, 1)
                    w.writerow({
                        't': t,
                        'timestamp': round(now, 6),
                        'ip': ip,
                        'rtt_ms': round(rtt, 3) if rtt is not None else '',
                        'reachable': reachable,
                        'loss_pct_last10': loss_pct,
                    })
                    # Emit node_saturated / node_recovered edge events
                    now_saturated = loss_pct >= self.SATURATED_LOSS_PCT
                    if now_saturated != saturated[ip]:
                        saturated[ip] = now_saturated
                        event = 'node_saturated' if now_saturated else 'node_recovered'
                        # Append to shared events.csv if it exists, else write header
                        write_header = not os.path.exists(events_path)
                        with open(events_path, 'a', newline='') as ef:
                            ew = csv.DictWriter(ef, fieldnames=['event', 't', 'timestamp', 'value'])
                            if write_header:
                                ew.writeheader()
                            ew.writerow({'event': event, 't': t, 'timestamp': round(now, 6), 'value': '{}:loss={}%'.format(ip, loss_pct)})
                f.flush()
                self._stop_event.wait(self.interval)


def write_baseline_summary(out, pir_samples, cpu_samples, false_positive_count, total_samples):
    summary = {
        "packet_in_rate": compute_stats(pir_samples),
        "controller_cpu_percent": compute_stats(cpu_samples),
        "false_positive_detections": false_positive_count,
        "total_samples": total_samples,
        "note": "Baseline run — no attack traffic. Use these values to calibrate threshold and establish normal operating range.",
    }
    path = os.path.join(out, 'baseline_summary.json')
    with open(path, 'w') as f:
        json.dump(summary, f, indent=2)
    print("\n=== Baseline Summary ===")
    print("  Packet-In rate  - mean: {}  min: {}  max: {}  stddev: {}".format(
        summary['packet_in_rate']['mean'],
        summary['packet_in_rate']['min'],
        summary['packet_in_rate']['max'],
        summary['packet_in_rate']['stddev'],
    ))
    print("  CPU %           - mean: {}  min: {}  max: {}  stddev: {}".format(
        summary['controller_cpu_percent']['mean'],
        summary['controller_cpu_percent']['min'],
        summary['controller_cpu_percent']['max'],
        summary['controller_cpu_percent']['stddev'],
    ))
    print("  False-positive mitigation triggers: {} / {} samples".format(false_positive_count, total_samples))
    suggested_threshold = (summary['packet_in_rate']['max'] or 0) * 3
    print("  Suggested threshold (max x3): {}".format(round(suggested_threshold, 1)))
    print("  Saved: {}\n".format(path))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--duration', type=float, required=True)
    p.add_argument('--interval', type=float, default=1.0)
    p.add_argument('--out', required=True)
    p.add_argument('--controller', default='http://127.0.0.1:8080')
    p.add_argument('--iface', default='', help='Interface connected toward controller, e.g. s1-ethX or eth1')
    p.add_argument('--threshold', type=float, default=None)
    p.add_argument('--baseline', action='store_true', help='Compute baseline statistics and write baseline_summary.json')
    p.add_argument('--switch-ips', default='', help='Comma-separated IPs to probe for switch/host RTT (writes switch_rtt.csv)')
    p.add_argument('--controller-wait', type=float, default=30.0, help='Seconds to wait for controller REST before starting collection')
    args=p.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # Wait for controller to be reachable before opening CSV files / starting the loop.
    wait_for_controller(args.controller, timeout=args.controller_wait)

    metrics_path=os.path.join(args.out,'controller_metrics.csv')
    status_path=os.path.join(args.out,'attack_status.csv')
    mitigation_path=os.path.join(args.out,'mitigation_metrics.csv')
    link_path=os.path.join(args.out,'controller_link_util.csv')
    events_path=os.path.join(args.out,'events.csv')
    mf=open(metrics_path,'w',newline=''); sf=open(status_path,'w',newline=''); gf=open(mitigation_path,'w',newline=''); lf=open(link_path,'w',newline=''); ef=open(events_path,'w',newline='')
    mw=csv.DictWriter(mf, fieldnames=['t','timestamp','packet_in_total','packet_in_rate','packet_in_threshold','controller_cpu_percent','connected_switches','known_hosts','learned_mac_entries','learned_flow_install_count','packet_out_count','mitigation_enabled','mitigation_active','attack_detected','manual_mitigation','mitigated_drop_count'])
    sw=csv.DictWriter(sf, fieldnames=['t','timestamp','phase','lockdown_active','attack_detected','mitigation_active','manual_mitigation','packet_in_rate','threshold_rate','attack_detection_time','mitigation_start_time'])
    gw=csv.DictWriter(gf, fieldnames=['t','timestamp','phase','lockdown_active','mitigated_drop_count','dropped_unknown_count','dropped_overrate_count','dropped_unknown_destination_count','trusted_source_count','source_seen_count_total','mitigated_source_count','rate_limited_ports_count','escalated_ports_count'])
    lw=csv.DictWriter(lf, fieldnames=['t','timestamp','iface','rx_pps','tx_pps','total_pps','rx_packets','tx_packets','rx_mbps','tx_mbps','total_mbps','rx_bytes','tx_bytes','rx_dropped','tx_dropped','rx_errors','tx_errors'])
    ew=csv.DictWriter(ef, fieldnames=['event','t','timestamp','value'])
    for w in (mw,sw,gw,lw,ew): w.writeheader()
    start=time.time(); prev_iface_stats=read_iface_stats(args.iface); prev_time=start
    # Track previous state for each flag so every on/off transition is recorded.
    prev_threshold_crossed=False; prev_detected=False; prev_mitigated=False
    prev_rate_limited_ports=0; prev_escalated_ports=0
    pir_samples=[]; cpu_samples=[]; false_positive_count=0; total_samples=0

    # Start switch RTT prober if IPs were provided.
    rtt_prober = None
    if args.switch_ips:
        ips = [ip.strip() for ip in args.switch_ips.split(',') if ip.strip()]
        if ips:
            rtt_prober = SwitchRTTProber(ips, args.out, start, interval=5.0)
            rtt_prober.start()

    while True:
        now=time.time(); t=now-start
        if t > args.duration: break
        try:
            stats=get_json(args.controller,'/stats')
            status=get_json(args.controller,'/attack/status')
            mit=get_json(args.controller,'/attack/metrics')
            row={k:stats.get(k,0) for k in mw.fieldnames if k not in ('t','timestamp')}
            row.update({'t':round(t,3),'timestamp':round(now,6)})
            mw.writerow(row); mf.flush()
            srow={k:status.get(k,'') for k in sw.fieldnames if k not in ('t','timestamp')}
            srow.update({'t':round(t,3),'timestamp':round(now,6)})
            sw.writerow(srow); sf.flush()
            grow=flat_mitigation(mit); grow.update({'t':round(t,3),'timestamp':round(now,6)})
            gw.writerow(grow); gf.flush()

            cur_rate_limited_ports = int(grow.get('rate_limited_ports_count', 0) or 0)
            cur_escalated_ports = int(grow.get('escalated_ports_count', 0) or 0)

            if cur_rate_limited_ports > 0 and prev_rate_limited_ports == 0:
                ew.writerow({'event': 'metering_started', 't': round(t,3), 'timestamp': round(now,6), 'value': cur_rate_limited_ports}); ef.flush()
            elif cur_rate_limited_ports == 0 and prev_rate_limited_ports > 0:
                ew.writerow({'event': 'metering_cleared', 't': round(t,3), 'timestamp': round(now,6), 'value': cur_rate_limited_ports}); ef.flush()

            if cur_escalated_ports > 0 and prev_escalated_ports == 0:
                ew.writerow({'event': 'escalation_started', 't': round(t,3), 'timestamp': round(now,6), 'value': cur_escalated_ports}); ef.flush()
            elif cur_escalated_ports == 0 and prev_escalated_ports > 0:
                ew.writerow({'event': 'escalation_cleared', 't': round(t,3), 'timestamp': round(now,6), 'value': cur_escalated_ports}); ef.flush()

            prev_rate_limited_ports = cur_rate_limited_ports
            prev_escalated_ports = cur_escalated_ports
            if args.baseline:
                pir=float(status.get('packet_in_rate',stats.get('packet_in_rate',0)) or 0)
                cpu=float(stats.get('controller_cpu_percent',0) or 0)
                pir_samples.append(pir); cpu_samples.append(cpu); total_samples+=1
                if bool(status.get('mitigation_active')): false_positive_count+=1
            thr = args.threshold if args.threshold is not None else status.get('threshold_rate', stats.get('packet_in_threshold'))
            pir = float(status.get('packet_in_rate', stats.get('packet_in_rate', 0)) or 0)
            # Record every state transition, not just the first occurrence.
            cur_threshold = thr is not None and pir >= float(thr)
            cur_detected = bool(status.get('attack_detected'))
            cur_mitigated = bool(status.get('mitigation_active'))
            if cur_threshold != prev_threshold_crossed:
                ew.writerow({'event': 'threshold_crossed' if cur_threshold else 'threshold_cleared', 't': round(t,3), 'timestamp': round(now,6), 'value': pir}); ef.flush()
                prev_threshold_crossed = cur_threshold
            if cur_detected != prev_detected:
                ew.writerow({'event': 'attack_detected' if cur_detected else 'attack_cleared', 't': round(t,3), 'timestamp': round(now,6), 'value': pir}); ef.flush()
                prev_detected = cur_detected
            if cur_mitigated != prev_mitigated:
                ew.writerow({'event': 'mitigation_active' if cur_mitigated else 'mitigation_ended', 't': round(t,3), 'timestamp': round(now,6), 'value': pir}); ef.flush()
                prev_mitigated = cur_mitigated
        except Exception as e:
            ew.writerow({'event':'collector_error','t':round(t,3),'timestamp':round(now,6),'value':str(e)[:120]}); ef.flush()
        cur_iface_stats=read_iface_stats(args.iface)
        if cur_iface_stats and prev_iface_stats:
            dt=max(0.001, now-prev_time)
            drx=cur_iface_stats['rx_bytes']-prev_iface_stats['rx_bytes']
            dtx=cur_iface_stats['tx_bytes']-prev_iface_stats['tx_bytes']
            drxp=cur_iface_stats['rx_packets']-prev_iface_stats['rx_packets']
            dtxp=cur_iface_stats['tx_packets']-prev_iface_stats['tx_packets']
            lw.writerow({
                't':round(t,3),'timestamp':round(now,6),'iface':args.iface,
                'rx_pps':round(drxp/dt,4),'tx_pps':round(dtxp/dt,4),
                'total_pps':round((drxp+dtxp)/dt,4),
                'rx_packets':cur_iface_stats['rx_packets'],'tx_packets':cur_iface_stats['tx_packets'],
                'rx_mbps':round(drx*8/dt/1e6,4),'tx_mbps':round(dtx*8/dt/1e6,4),
                'total_mbps':round((drx+dtx)*8/dt/1e6,4),
                'rx_bytes':cur_iface_stats['rx_bytes'],'tx_bytes':cur_iface_stats['tx_bytes'],
                'rx_dropped':cur_iface_stats['rx_dropped'],'tx_dropped':cur_iface_stats['tx_dropped'],
                'rx_errors':cur_iface_stats['rx_errors'],'tx_errors':cur_iface_stats['tx_errors'],
            }); lf.flush()
        prev_iface_stats=cur_iface_stats; prev_time=now
        time.sleep(args.interval)

    if rtt_prober is not None:
        rtt_prober.stop()
        rtt_prober.join(timeout=5)
    for f in (mf,sf,gf,lf,ef): f.close()
    if args.baseline: write_baseline_summary(args.out,pir_samples,cpu_samples,false_positive_count,total_samples)
if __name__=='__main__': main()
