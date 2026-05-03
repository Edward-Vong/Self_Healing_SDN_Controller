#!/usr/bin/env python3
import argparse, csv, json, math, os, time, urllib.request, urllib.error, subprocess, re

def get_json(base, path):
    url = base.rstrip('/') + path
    with urllib.request.urlopen(url, timeout=2) as r:
        return json.loads(r.read().decode('utf-8'))

def read_iface_bytes(iface):
    if not iface:
        return None
    base = f'/sys/class/net/{iface}/statistics'
    try:
        with open(os.path.join(base,'rx_bytes')) as f: rx=int(f.read().strip())
        with open(os.path.join(base,'tx_bytes')) as f: tx=int(f.read().strip())
        return rx, tx
    except Exception:
        return None

def flat_mitigation(m):
    mit = m.get('mitigation', {}) if isinstance(m, dict) else {}
    rate_limited = []
    escalated = []
    for dpid, ports in (mit.get('rate_limited_ports') or {}).items():
        rate_limited.extend(ports)
    for dpid, ports in (mit.get('escalated_ports') or {}).items():
        escalated.extend(ports)
    return {
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
    print(f"  Packet-In rate  — mean: {summary['packet_in_rate']['mean']}  min: {summary['packet_in_rate']['min']}  max: {summary['packet_in_rate']['max']}  stddev: {summary['packet_in_rate']['stddev']}")
    print(f"  CPU %           — mean: {summary['controller_cpu_percent']['mean']}  min: {summary['controller_cpu_percent']['min']}  max: {summary['controller_cpu_percent']['max']}  stddev: {summary['controller_cpu_percent']['stddev']}")
    print(f"  False-positive mitigation triggers: {false_positive_count} / {total_samples} samples")
    suggested_threshold = (summary['packet_in_rate']['max'] or 0) * 3
    print(f"  Suggested threshold (max x3): {round(suggested_threshold, 1)}")
    print(f"  Saved: {path}\n")

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--duration', type=float, required=True)
    p.add_argument('--interval', type=float, default=1.0)
    p.add_argument('--out', required=True)
    p.add_argument('--controller', default='http://127.0.0.1:8080')
    p.add_argument('--iface', default='', help='Interface connected toward controller, e.g. s1-ethX or eth1')
    p.add_argument('--threshold', type=float, default=None)
    p.add_argument('--baseline', action='store_true', help='Compute baseline statistics and write baseline_summary.json')
    args=p.parse_args()
    os.makedirs(args.out, exist_ok=True)
    metrics_path=os.path.join(args.out,'controller_metrics.csv')
    status_path=os.path.join(args.out,'attack_status.csv')
    mitigation_path=os.path.join(args.out,'mitigation_metrics.csv')
    link_path=os.path.join(args.out,'controller_link_util.csv')
    events_path=os.path.join(args.out,'events.csv')
    mf=open(metrics_path,'w',newline=''); sf=open(status_path,'w',newline=''); gf=open(mitigation_path,'w',newline=''); lf=open(link_path,'w',newline=''); ef=open(events_path,'w',newline='')
    mw=csv.DictWriter(mf, fieldnames=['t','timestamp','packet_in_total','packet_in_rate','packet_in_threshold','controller_cpu_percent','connected_switches','known_hosts','learned_mac_entries','learned_flow_install_count','packet_out_count','mitigation_enabled','mitigation_active','attack_detected','manual_mitigation','mitigated_drop_count'])
    sw=csv.DictWriter(sf, fieldnames=['t','timestamp','attack_detected','mitigation_active','manual_mitigation','packet_in_rate','threshold_rate','attack_detection_time','mitigation_start_time'])
    gw=csv.DictWriter(gf, fieldnames=['t','timestamp','mitigated_drop_count','dropped_unknown_count','dropped_overrate_count','dropped_unknown_destination_count','trusted_source_count','source_seen_count_total','mitigated_source_count','rate_limited_ports_count','escalated_ports_count'])
    lw=csv.DictWriter(lf, fieldnames=['t','timestamp','iface','rx_mbps','tx_mbps','total_mbps','rx_bytes','tx_bytes'])
    ew=csv.DictWriter(ef, fieldnames=['event','t','timestamp','value'])
    for w in (mw,sw,gw,lw,ew): w.writeheader()
    start=time.time(); prev_iface=read_iface_bytes(args.iface); prev_time=start; threshold_crossed=False; detected=False; mitigated=False
    pir_samples=[]; cpu_samples=[]; false_positive_count=0; total_samples=0
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
            if args.baseline:
                pir=float(status.get('packet_in_rate',stats.get('packet_in_rate',0)) or 0)
                cpu=float(stats.get('controller_cpu_percent',0) or 0)
                pir_samples.append(pir); cpu_samples.append(cpu); total_samples+=1
                if bool(status.get('mitigation_active')): false_positive_count+=1
            thr = args.threshold if args.threshold is not None else status.get('threshold_rate', stats.get('packet_in_threshold'))
            pir = float(status.get('packet_in_rate', stats.get('packet_in_rate', 0)) or 0)
            if not threshold_crossed and thr is not None and pir >= float(thr):
                ew.writerow({'event':'threshold_crossed','t':round(t,3),'timestamp':round(now,6),'value':pir}); threshold_crossed=True; ef.flush()
            if not detected and bool(status.get('attack_detected')):
                ew.writerow({'event':'attack_detected','t':round(t,3),'timestamp':round(now,6),'value':pir}); detected=True; ef.flush()
            if not mitigated and bool(status.get('mitigation_active')):
                ew.writerow({'event':'mitigation_active','t':round(t,3),'timestamp':round(now,6),'value':pir}); mitigated=True; ef.flush()
        except Exception as e:
            ew.writerow({'event':'collector_error','t':round(t,3),'timestamp':round(now,6),'value':str(e)[:120]}); ef.flush()
        cur_iface=read_iface_bytes(args.iface)
        if cur_iface and prev_iface:
            dt=max(0.001, now-prev_time); drx=cur_iface[0]-prev_iface[0]; dtx=cur_iface[1]-prev_iface[1]
            lw.writerow({'t':round(t,3),'timestamp':round(now,6),'iface':args.iface,'rx_mbps':round(drx*8/dt/1e6,4),'tx_mbps':round(dtx*8/dt/1e6,4),'total_mbps':round((drx+dtx)*8/dt/1e6,4),'rx_bytes':cur_iface[0],'tx_bytes':cur_iface[1]}); lf.flush()
        prev_iface=cur_iface; prev_time=now
        time.sleep(args.interval)
    for f in (mf,sf,gf,lf,ef): f.close()
    if args.baseline: write_baseline_summary(args.out,pir_samples,cpu_samples,false_positive_count,total_samples)
if __name__=='__main__': main()
