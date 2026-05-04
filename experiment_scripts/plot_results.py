#!/usr/bin/env python3
import argparse, csv, os, math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

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

def save_line(rows, x, ys, labels, title, ylabel, out):
    if not rows: return False
    plt.figure()
    xs=[num(r,x) for r in rows]
    for y,l in zip(ys,labels): plt.plot(xs,[num(r,y) for r in rows],label=l)
    plt.xlabel('time (s)' if x=='t' else x); plt.ylabel(ylabel); plt.title(title); plt.grid(True); plt.legend(); plt.tight_layout(); plt.savefig(out); plt.close(); return True

def main():
    p=argparse.ArgumentParser(); p.add_argument('input_dir'); p.add_argument('--output', default='')
    a=p.parse_args(); d=a.input_dir; out=a.output or d; os.makedirs(out, exist_ok=True)
   
    metrics=read_csv(os.path.join(d,'controller_metrics.csv'))
    status=read_csv(os.path.join(d,'attack_status.csv'))
    mit=read_csv(os.path.join(d,'mitigation_metrics.csv'))
    link=read_csv(os.path.join(d,'controller_link_util.csv'))
    events=read_csv(os.path.join(d,'events.csv'))
    
    made=[]
    
    if status:
        plt.figure(figsize=(14, 6))
        xs=[num(r,'t') for r in status]
        ys=[num(r,'packet_in_rate') for r in status]
        plt.plot(xs,ys,label='Packet-In rate')
        thr=[num(r,'threshold_rate') for r in status if r.get('threshold_rate') not in ('',None)]
        if thr: plt.axhline(thr[0], linestyle='--', label='Threshold')
        
        # Define colors for each event
        event_colors = {
            'threshold_crossed': 'red',
            'attack_detected': 'orange',
            'mitigation_active': 'green',
            'attack_ended': 'blue'
        }
        
        for e in events:
            if e.get('event') in ('attack_detected','threshold_crossed','mitigation_active','attack_ended'):
                color = event_colors.get(e.get('event'), 'gray')
                plt.axvline(num(e,'t'), linestyle=':', color=color, label=e.get('event'))
        
        # Detect when mitigation_active changes from true to false
        mitigation_inactive_time = None
        for i in range(len(status)-1):
            curr_active = boolish(status[i].get('mitigation_active', False))
            next_active = boolish(status[i+1].get('mitigation_active', False))
            if curr_active and not next_active:
                mitigation_inactive_time = num(status[i+1], 't')
                break
        if mitigation_inactive_time:
            plt.axvline(mitigation_inactive_time, linestyle='--', color='purple', label='mitigation_inactive')
        
        plt.xlabel('time (s)'); plt.ylabel('Packet-In events/sec'); plt.title('Attack detection: Packet-In rate over time'); plt.grid(True); plt.legend(); plt.tight_layout(); path=os.path.join(out,'packetin_rate_detection.png'); plt.savefig(path); plt.close(); made.append(path)
    
    if metrics:
        plt.figure(figsize=(14, 6))
        xs = [num(r, 't') for r in metrics]
        ys = [num(r, 'controller_cpu_percent') for r in metrics]

        plt.plot(xs, ys, label='CPU %')

        ev_times = event_times(events, ['threshold_crossed', 'attack_detected', 'mitigation_active', 'attack_ended'])
        
        # Define colors for each event
        event_colors = {
            'threshold_crossed': 'red',
            'attack_detected': 'orange',
            'mitigation_active': 'green',
            'attack_ended': 'blue'
        }
        
        for label, t in ev_times.items():
            color = event_colors.get(label, 'gray')
            plt.axvline(t, linestyle=':', color=color, label=label)
        
        # Detect when mitigation_active changes from true to false
        mitigation_inactive_time = None
        if status:
            for i in range(len(status)-1):
                curr_active = boolish(status[i].get('mitigation_active', False))
                next_active = boolish(status[i+1].get('mitigation_active', False))
                if curr_active and not next_active:
                    mitigation_inactive_time = num(status[i+1], 't')
                    break
        if mitigation_inactive_time:
            plt.axvline(mitigation_inactive_time, linestyle='--', color='purple', label='mitigation_inactive')

        plt.xlabel('time (s)')
        plt.ylabel('CPU %')
        plt.title('Controller CPU over time')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()

        path = os.path.join(out, 'cpu_over_time.png')
        plt.savefig(path)
        plt.close()
        made.append(path)
    
    if mit:
        plt.figure(figsize=(14, 6))
        xs = [num(r, 't') for r in mit]
        
        # Calculate rates (drops per second) for each metric
        mitigated_rates = [0]
        unknown_rates = [0]
        overrate_rates = [0]
        
        for i in range(1, len(mit)):
            dt = xs[i] - xs[i-1]
            if dt > 0:
                mitigated_rates.append((num(mit[i], 'mitigated_drop_count') - num(mit[i-1], 'mitigated_drop_count')) / dt)
                unknown_rates.append((num(mit[i], 'dropped_unknown_count') - num(mit[i-1], 'dropped_unknown_count')) / dt)
                overrate_rates.append((num(mit[i], 'dropped_overrate_count') - num(mit[i-1], 'dropped_overrate_count')) / dt)
            else:
                mitigated_rates.append(0)
                unknown_rates.append(0)
                overrate_rates.append(0)
        
        plt.plot(xs, mitigated_rates, label='total drops/sec')
        plt.plot(xs, unknown_rates, label='unknown source drops/sec')
        plt.plot(xs, overrate_rates, label='over-rate drops/sec')
        
        plt.xlabel('time (s)')
        plt.ylabel('drops/sec')
        plt.title('Mitigation drops rate over time')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
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

        plt.figure()
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
    
    if link and save_line(link,'t',['total_mbps','rx_mbps','tx_mbps'],['total Mbps','rx Mbps','tx Mbps'],'Controller link utilization over time','Mbps',os.path.join(out,'controller_link_util_over_time.png')): made.append(os.path.join(out,'controller_link_util_over_time.png'))
    # parse ping RTT logs
    
    for name in ('ping_existing','ping_new'):
        # combined RTT graph for existing + new legitimate traffic
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

        plt.figure()
        has_ping = False

        for name, offset in [('ping_existing', 0), ('ping_new', valid_new_delay)]:
            log = os.path.join(d, '{}.log'.format(name))
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
                csvp = os.path.join(d, '{}.csv'.format(name))
                with open(csvp, 'w', newline='') as f:
                    w = csv.DictWriter(f, fieldnames=['t', 'rtt_ms'])
                    w.writeheader()
                    w.writerows(rows)

                label = 'existing trusted flow' if name == 'ping_existing' else 'new trusted flow'
                plt.plot([r['t'] for r in rows], [r['rtt_ms'] for r in rows], label=label)

        if has_ping:
            plt.axvline(attack_delay, linestyle='--', label='attack starts')

            ev_times = event_times(events, ['mitigation_active'])
            if 'mitigation_active' in ev_times:
                plt.axvline(ev_times['mitigation_active'], linestyle=':', label='mitigation starts')

            mitigation_inactive_time = None
            if status:
                for i in range(len(status)-1):
                    curr_active = boolish(status[i].get('mitigation_active', False))
                    next_active = boolish(status[i+1].get('mitigation_active', False))
                    if curr_active and not next_active:
                        mitigation_inactive_time = num(status[i+1], 't')
                        break
            if mitigation_inactive_time is not None:
                plt.axvline(mitigation_inactive_time, linestyle='--', color='purple', label='mitigation_inactive')

            plt.xlabel('time (s)')
            plt.ylabel('RTT ms')
            plt.title('Legitimate Traffic RTT During Attack and Recovery')
            plt.grid(True)
            plt.legend()
            plt.tight_layout()
            
            # Widen the figure by adjusting it before saving
            fig = plt.gcf()
            fig.set_size_inches(14, 6)
            plt.tight_layout()

            path = os.path.join(out, 'legitimate_rtt_combined.png')
            plt.savefig(path)
            plt.close()
            made.append(path)
    

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
        rows = parse_iperf_log(os.path.join(d, '{}.log'.format(log_name)), offset)
        if not rows:
            continue
        has_iperf = True
        csvp = os.path.join(d, '{}.csv'.format(log_name))
        with open(csvp, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['t', 'mbps'])
            w.writeheader()
            w.writerows(rows)
        plt.plot([r['t'] for r in rows], [r['mbps'] for r in rows], label=label)

    if has_iperf:
        plt.axvline(attack_delay, linestyle='--', label='attack starts')
        ev_times = event_times(events, ['mitigation_active'])
        if 'mitigation_active' in ev_times:
            plt.axvline(ev_times['mitigation_active'], linestyle=':', label='mitigation starts')
        plt.xlabel('time (s)')
        plt.ylabel('Mbits/sec')
        plt.title('Trusted Throughput During Attack and Recovery')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        path = os.path.join(out, 'trusted_throughput_combined.png')
        plt.savefig(path)
        plt.close()
        made.append(path)
    else:
        plt.close()
        made.append(path)
    
    if mit:
        plt.figure(figsize=(14, 6))
        xs=[num(r,'t') for r in mit]
        rate_limited=[num(r,'rate_limited_ports_count') for r in mit]
        escalated=[num(r,'escalated_ports_count') for r in mit]
        
        plt.plot(xs, rate_limited, label='rate-limited ports', marker='o')
        plt.plot(xs, escalated, label='escalated (drop) ports', marker='s')
        
        ev_times=event_times(events, ['mitigation_active'])
        if 'mitigation_active' in ev_times:
            plt.axvline(ev_times['mitigation_active'], linestyle=':', color='green', alpha=0.5, label='mitigation starts')
        
        plt.xlabel('time (s)')
        plt.ylabel('number of ports')
        plt.title('Port-level mitigation escalation over time')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        path=os.path.join(out,'mitigation_port_escalation.png')
        plt.savefig(path)
        plt.close()
        made.append(path)

    if events:
        order=['threshold_crossed','attack_detected','mitigation_active']
        evs=[e for e in events if e.get('event') in order]
        if evs:
            plt.figure(figsize=(10, 6))
            plt.scatter([num(e,'t') for e in evs],[order.index(e.get('event')) for e in evs], s=100)
            plt.yticks(range(len(order)), order)
            plt.xlabel('time (s)')
            plt.title('Detection and response timeline')
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
