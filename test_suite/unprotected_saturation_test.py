#!/usr/bin/env python3
"""
Unprotected saturation test for the Self-Healing SDN Controller.

Modes:
1) Stepped mode (default): no args needed. Walks a PPS ladder and looks
    for saturation/plateau behavior.
2) Fixed-rate mode (--pps N): sends traffic at N pps for 90 seconds and
    reports aggregate stats.
3) Granularity mode (--granularity): wait for trust_test.py start signal,
    then run fixed-rate saturation.
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import threading
import time

try:
    from test_suite.test_common import (
        get_stats as common_get_stats,
        parse_cpu_percent as common_parse_cpu_percent,
        reset_controller as common_reset_controller,
        set_mitigation_enabled as common_set_mitigation_enabled,
    )
except ModuleNotFoundError:
    from test_common import (
        get_stats as common_get_stats,
        parse_cpu_percent as common_parse_cpu_percent,
        reset_controller as common_reset_controller,
        set_mitigation_enabled as common_set_mitigation_enabled,
    )

# ---------------------------------------------------------------------------
# Configuration - edit these to match your setup
# ---------------------------------------------------------------------------
IFACE = "eth1"  # data-plane interface facing OVS
CONTROLLER_API = "http://128.110.223.3:8080"  # Ryu REST API

# Default stepped-mode ladder.
RAMP_STEPS = [50, 100, 250, 500, 1000, 2000, 5000, 10000]
STEP_DURATION = 10  # seconds rate must stay at target once reached
STEP_TIMEOUT = 30  # abort current/overall test if target not reached in this time
RATE_TOLERANCE = 0.95  # consider target reached at >= target_pps * RATE_TOLERANCE
POLL_INTERVAL = 2  # seconds between REST polls within a step
CPU_STAT_KEY = "controller_cpu_percent"
REQUIRE_CPU_METRICS = True
FIXED_MODE_SECONDS = 90
GRANULARITY_HOST = "0.0.0.0"
GRANULARITY_PORT = 9010
GRANULARITY_TOKEN = "START"
GRANULARITY_WAIT_TIMEOUT = 180

# Destination IP used for hping3 flood.
DST_IP = "10.0.0.1"

# Delay measurement + hping3 settings
DELAY_PROBE_HOST = CONTROLLER_API.split("://")[-1].split(":")[0]
DELAY_PROBE_COUNT = 10
DELAY_PROBE_TIMEOUT = 2
DELAY_SAMPLE_INTERVAL = 15
HPING3_BIN = "hping3"
# ---------------------------------------------------------------------------


def get_stats():
    return common_get_stats(CONTROLLER_API)


def parse_cpu_percent(stats):
    return common_parse_cpu_percent(stats, CPU_STAT_KEY)


def set_mitigation_enabled(enabled):
    return common_set_mitigation_enabled(CONTROLLER_API, enabled)


def reset_controller():
    return common_reset_controller(CONTROLLER_API)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run unprotected saturation test for the Self-Healing SDN Controller."
    )
    parser.add_argument(
        "--pps",
        type=int,
        default=0,
        help="Fixed-rate mode: send this PPS for 90 seconds (example: --pps 1300)",
    )
    parser.add_argument(
        "--granularity",
        action="store_true",
        help="Wait for trust_test.py handshake before starting saturation",
    )
    parser.add_argument("--skip-reset-controller", action="store_true")
    return parser.parse_args()


def wait_for_granularity_start(host, port, token, timeout_sec):
    """Block until a matching START token is received over TCP."""
    deadline = time.time() + timeout_sec
    print(f"Granularity wait: listen={host}:{port} token='{token}' timeout={timeout_sec}s")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)

        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            server.settimeout(min(1.0, remaining))
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue

            with conn:
                conn.settimeout(2.0)
                try:
                    payload = conn.recv(64).decode("utf-8", errors="ignore").strip()
                except OSError:
                    payload = ""

                if payload == token:
                    try:
                        conn.sendall(b"ACK\n")
                    except OSError:
                        pass
                    print(f"Granularity signal accepted from {addr[0]}:{addr[1]}")
                    return True

                print(f"Granularity signal ignored from {addr[0]}:{addr[1]}: token='{payload}'")

    return False


# ---------------------------------------------------------------------------
# RTT / delay measurement
# ---------------------------------------------------------------------------

def measure_rtt(host=None, count=DELAY_PROBE_COUNT, timeout_per_probe=DELAY_PROBE_TIMEOUT):
    """
    Measure ICMP round-trip time to host using the system ping command.
    Returns a dict {min_ms, avg_ms, max_ms, loss_pct} or None on failure.
    """
    if host is None:
        host = DELAY_PROBE_HOST
    ping_cmd = ["ping", "-c", str(count), "-W", str(timeout_per_probe), host]
    if os.name == "nt":
        ping_cmd = ["ping", "-n", str(count), "-w", str(int(timeout_per_probe * 1000)), host]

    try:
        result = subprocess.run(
            ping_cmd,
            capture_output=True,
            text=True,
            timeout=count * (timeout_per_probe + 1) + 5,
        )
        output = result.stdout
        m_rtt = re.search(
            r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", output
        )
        if not m_rtt:
            # Windows ping summary format.
            m_win = re.search(
                r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
                output,
            )
            if m_win:
                min_ms = float(m_win.group(1))
                max_ms = float(m_win.group(2))
                avg_ms = float(m_win.group(3))
                m_loss = re.search(r"\((\d+)%\s*loss\)", output, flags=re.IGNORECASE)
                return {
                    "min_ms": round(min_ms, 3),
                    "avg_ms": round(avg_ms, 3),
                    "max_ms": round(max_ms, 3),
                    "loss_pct": round(float(m_loss.group(1)), 1) if m_loss else 100.0,
                }
        m_loss = re.search(r"([\d.]+)% packet loss", output)
        if m_rtt:
            return {
                "min_ms": round(float(m_rtt.group(1)), 3),
                "avg_ms": round(float(m_rtt.group(2)), 3),
                "max_ms": round(float(m_rtt.group(3)), 3),
                "loss_pct": round(float(m_loss.group(1)), 1) if m_loss else 100.0,
            }
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        print(f"  [RTT] measure_rtt failed: {exc}")
        return None


def _delay_sampler(host, interval, stop_event, results):
    """Background thread: collect periodic RTT samples while flood is running."""
    while not stop_event.is_set():
        sample = measure_rtt(host, count=3, timeout_per_probe=1)
        if sample is not None:
            results.append(sample)
        stop_event.wait(interval)


def _aggregate_delay(samples):
    if not samples:
        return None
    return {
        "min_ms": round(min(s["min_ms"] for s in samples), 3),
        "avg_ms": round(sum(s["avg_ms"] for s in samples) / len(samples), 3),
        "max_ms": round(max(s["max_ms"] for s in samples), 3),
        "loss_pct": round(sum(s["loss_pct"] for s in samples) / len(samples), 1),
        "n_samples": len(samples),
    }


def _rtt_live_tag(delay_samples):
    if not delay_samples:
        return ""
    return f"  rtt={delay_samples[-1]['avg_ms']}ms"


def _rtt_delta_str(under_attack, baseline):
    if not under_attack or not baseline:
        return "n/a"
    base = baseline.get("avg_ms")
    atk = under_attack.get("avg_ms")
    if base is None or atk is None or base <= 0:
        return "n/a"
    delta = ((atk - base) / base) * 100.0
    return f"{delta:+.1f}%"


def _print_delay_section(baseline, under_attack):
    print("-" * 60)
    print("Network Delay")
    print("-" * 60)
    if baseline:
        print(
            f"Baseline RTT    : avg={baseline['avg_ms']}ms  min={baseline['min_ms']}ms  "
            f"max={baseline['max_ms']}ms  loss={baseline['loss_pct']}%"
        )
    else:
        print("Baseline RTT    : measurement failed")

    if under_attack:
        print(
            f"Under-Attack RTT: avg={under_attack['avg_ms']}ms  min={under_attack['min_ms']}ms  "
            f"max={under_attack['max_ms']}ms  loss={under_attack['loss_pct']}%"
        )
        print(
            f"  (averaged over {under_attack['n_samples']} in-flight sample(s), "
            f"1 sample every {DELAY_SAMPLE_INTERVAL}s)"
        )
    else:
        print("Under-Attack RTT: no samples collected (flood too short or host unreachable?)")

    if baseline and under_attack and baseline.get("avg_ms", 0) > 0:
        degradation = ((under_attack["avg_ms"] - baseline["avg_ms"]) / baseline["avg_ms"]) * 100
        print(f"Avg RTT change  : {degradation:+.1f}%")


# ---------------------------------------------------------------------------
# Flood backend
# ---------------------------------------------------------------------------

def flood_hping3(stop_event, dst_ip=DST_IP, iface=IFACE):
    """
    Launch hping3 in UDP flood mode; terminate when stop_event fires.
    Command:
      hping3 --flood --udp -p 9999 -d 200 --rand-source --interface <iface> <dst_ip>
    """
    cmd = [
        HPING3_BIN,
        "--flood",
        "--udp",
        "-p",
        "9999",
        "-d",
        "200",
        "--rand-source",
        "--interface",
        iface,
        dst_ip,
    ]

    print(f"  [hping3] cmd: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        print(f"  [hping3] ERROR: '{HPING3_BIN}' not found. Install hping3 and retry.")
        stop_event.wait()
        return

    stop_event.wait()
    proc.terminate()
    try:
        _, stderr_bytes = proc.communicate(timeout=5)
        if stderr_bytes:
            for line in stderr_bytes.decode("utf-8", errors="ignore").strip().splitlines()[-3:]:
                if line.strip():
                    print(f"  [hping3] {line}")
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()


def _start_flood_and_sampler():
    stop_event = threading.Event()
    delay_samples = []

    flood_thread = threading.Thread(
        target=flood_hping3,
        args=(stop_event,),
        daemon=True,
    )
    sampler_thread = threading.Thread(
        target=_delay_sampler,
        args=(DELAY_PROBE_HOST, DELAY_SAMPLE_INTERVAL, stop_event, delay_samples),
        daemon=True,
    )

    flood_thread.start()
    sampler_thread.start()
    return stop_event, flood_thread, sampler_thread, delay_samples


def _stop_flood_and_sampler(stop_event, flood_thread, sampler_thread):
    stop_event.set()
    flood_thread.join(timeout=3)
    sampler_thread.join(timeout=DELAY_PROBE_COUNT * (DELAY_PROBE_TIMEOUT + 1) + 10)


def run_step(target_pps, baseline_rtt):
    """
    Flood until measured packet_in rate reaches tolerated target and remains
    there for STEP_DURATION seconds, or until STEP_TIMEOUT is exceeded.
    """
    stop_event, flood_thread, sampler_thread, delay_samples = _start_flood_and_sampler()

    rates = []
    cpu_rates = []
    required_rate = target_pps * RATE_TOLERANCE
    step_start = time.time()
    stable_since = None
    reached_target = False
    time_to_reach = None
    hold_time = 0.0

    while True:
        now = time.time()
        elapsed = now - step_start
        if elapsed > STEP_TIMEOUT:
            break

        stats = get_stats()
        if stats:
            rate = stats.get("packet_in_rate", 0)
            cpu = parse_cpu_percent(stats)
            rates.append(rate)
            mit_tag = "  [MITIGATION ACTIVE]" if stats.get("mitigation_active") else ""
            rtt_tag = _rtt_live_tag(delay_samples)
            if cpu is not None:
                cpu_rates.append(cpu)
                print(
                    f"    target={target_pps} pps  measured pi_rate={rate}/s  "
                    f"cpu={cpu}%{rtt_tag}{mit_tag}"
                )
            else:
                print(
                    f"    target={target_pps} pps  measured pi_rate={rate}/s"
                    f"{rtt_tag}{mit_tag}"
                )

            if rate >= required_rate:
                if stable_since is None:
                    stable_since = now
                    reached_target = True
                    time_to_reach = now - step_start
                hold_time = now - stable_since
                if hold_time >= STEP_DURATION:
                    break
            else:
                stable_since = None
                hold_time = 0.0

        time.sleep(POLL_INTERVAL)

    _stop_flood_and_sampler(stop_event, flood_thread, sampler_thread)

    avg_rate = round(sum(rates) / len(rates), 2) if rates else 0
    peak_rate = round(max(rates), 2) if rates else 0
    avg_cpu = round(sum(cpu_rates) / len(cpu_rates), 2) if cpu_rates else None
    peak_cpu = round(max(cpu_rates), 2) if cpu_rates else None

    return {
        "target_pps": target_pps,
        "required_pi_rate": round(required_rate, 2),
        "avg_pi_rate": avg_rate,
        "peak_pi_rate": peak_rate,
        "avg_cpu_percent": avg_cpu,
        "peak_cpu_percent": peak_cpu,
        "reached_and_held": reached_target and hold_time >= STEP_DURATION,
        "time_to_reach_s": round(time_to_reach, 2) if time_to_reach is not None else None,
        "hold_time_s": round(hold_time, 2),
        "delay_baseline": baseline_rtt,
        "delay_under_attack": _aggregate_delay(delay_samples),
    }


def run_fixed_rate(run_seconds, baseline_rtt):
    """
    Run flood for run_seconds and return aggregate stats for the window.
    """
    stop_event, flood_thread, sampler_thread, delay_samples = _start_flood_and_sampler()

    rates = []
    cpu_rates = []
    start = time.time()

    while time.time() - start < run_seconds:
        stats = get_stats()
        if stats:
            rate = stats.get("packet_in_rate", 0)
            cpu = parse_cpu_percent(stats)
            rates.append(rate)
            rtt_tag = _rtt_live_tag(delay_samples)
            if cpu is not None:
                cpu_rates.append(cpu)
                print(f"    flood=udp --flood  measured pi_rate={rate}/s  cpu={cpu}%{rtt_tag}")
            else:
                print(f"    flood=udp --flood  measured pi_rate={rate}/s{rtt_tag}")
        time.sleep(POLL_INTERVAL)

    _stop_flood_and_sampler(stop_event, flood_thread, sampler_thread)

    avg_rate = round(sum(rates) / len(rates), 2) if rates else 0
    peak_rate = round(max(rates), 2) if rates else 0
    avg_cpu = round(sum(cpu_rates) / len(cpu_rates), 2) if cpu_rates else None
    peak_cpu = round(max(cpu_rates), 2) if cpu_rates else None

    return {
        "avg_pi_rate": avg_rate,
        "peak_pi_rate": peak_rate,
        "avg_cpu_percent": avg_cpu,
        "peak_cpu_percent": peak_cpu,
        "delay_baseline": baseline_rtt,
        "delay_under_attack": _aggregate_delay(delay_samples),
    }


def prepare_controller(skip_reset_controller):
    """Shared pre-flight: connectivity check, disable mitigation, optional reset."""
    stats = get_stats()
    if stats is None:
        print("ERROR: Cannot reach Ryu REST API. Is the controller running?")
        sys.exit(1)

    initial_cpu = parse_cpu_percent(stats)
    if REQUIRE_CPU_METRICS and initial_cpu is None:
        keys = ", ".join(sorted(stats.keys())) if isinstance(stats, dict) else "<non-dict response>"
        print(f"ERROR: /stats is missing a numeric '{CPU_STAT_KEY}' value.")
        print(f"       Returned keys: {keys}")
        print("       Restart the controller process that serves this API and rerun the test.")
        sys.exit(2)

    print(f"Controller reachable - uptime={stats.get('uptime_seconds')}s")
    print()

    if not set_mitigation_enabled(False):
        print("ERROR: Could not disable mitigation - aborting to avoid protection bias.")
        sys.exit(3)
    if not skip_reset_controller:
        if not reset_controller():
            print("ERROR: Could not reset controller state - aborting.")
            sys.exit(4)
    else:
        print("WARNING: Skipping controller reset; prior controller state is preserved.")

    verify = get_stats()
    mitigation_enabled = verify.get("mitigation_enabled") if verify else None
    if mitigation_enabled is not False:
        print(f"ERROR: Controller mitigation_enabled is {mitigation_enabled!r}, expected False.")
        print("       Restart the controller and rerun the test.")
        sys.exit(5)
    time.sleep(1)


def main():
    args = parse_args()

    if args.pps < 0:
        print("ERROR: --pps must be >= 0.")
        sys.exit(2)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ERROR: hping3 requires raw-socket privileges.")
        print("       Run with: sudo python3 ./test_suite/unprotected_saturation_test.py")
        sys.exit(1)

    print(f"Interface      : {IFACE}")
    print(f"Controller API : {CONTROLLER_API}")
    print("Flood backend  : hping3 udp --flood --rand-source")

    prepare_controller(args.skip_reset_controller)

    print(f"[Delay] Measuring baseline RTT to {DELAY_PROBE_HOST} ...")
    baseline_rtt = measure_rtt()
    if baseline_rtt:
        print(
            f"[Delay] Baseline: avg={baseline_rtt['avg_ms']}ms  "
            f"min={baseline_rtt['min_ms']}ms  max={baseline_rtt['max_ms']}ms  "
            f"loss={baseline_rtt['loss_pct']}%"
        )
    else:
        print("[Delay] Baseline RTT measurement failed.")

    print()

    if args.granularity:
        if args.pps <= 0:
            print("ERROR: --granularity requires fixed-rate mode: provide --pps N")
            sys.exit(2)
        started = wait_for_granularity_start(
            GRANULARITY_HOST,
            GRANULARITY_PORT,
            GRANULARITY_TOKEN,
            GRANULARITY_WAIT_TIMEOUT,
        )
        if not started:
            print("ERROR: Timed out waiting for granularity start signal.")
            sys.exit(6)
        print()

    # Fixed-rate mode: --pps N
    if args.pps > 0:
        print("Mode          : FIXED")
        print(f"Requested PPS : {args.pps}")
        print(f"Duration      : {FIXED_MODE_SECONDS}s")
        print()

        try:
            result = run_fixed_rate(
                run_seconds=FIXED_MODE_SECONDS,
                baseline_rtt=baseline_rtt,
            )
        finally:
            set_mitigation_enabled(True)

        avg_cpu = result["avg_cpu_percent"]
        peak_cpu = result["peak_cpu_percent"]
        avg_cpu_str = f"{avg_cpu}%" if avg_cpu is not None else "n/a"
        peak_cpu_str = f"{peak_cpu}%" if peak_cpu is not None else "n/a"

        print("\n" + "=" * 60)
        print("Fixed-Rate Saturation Summary")
        print("-" * 60)
        print("Flood backend : hping3 udp --flood --rand-source")
        print(f"Requested PPS : {args.pps}")
        print(f"Avg PI/s      : {result['avg_pi_rate']}")
        print(f"Peak PI/s     : {result['peak_pi_rate']}")
        print(f"Avg CPU%      : {avg_cpu_str}")
        print(f"Peak CPU%     : {peak_cpu_str}")
        _print_delay_section(result["delay_baseline"], result["delay_under_attack"])
        print("=" * 60)

        return

    # Default stepped mode
    print("Mode          : STEPPED")
    print(f"Ramp steps    : {RAMP_STEPS} pps")
    print(f"Rate tolerance: {int(RATE_TOLERANCE * 100)}% of target")
    print(f"Hold duration : {STEP_DURATION}s at target")
    print(f"Step timeout  : {STEP_TIMEOUT}s max to reach/hold target")
    print()

    rows = []
    top_hdr = f"{'Target PPS':>12}  {'Avg PI Rate':>12}  {'Avg CPU %':>10}  {'RTT avg':>10}"
    top_sep = "-" * len(top_hdr)
    print(top_hdr)
    print(top_sep)

    try:
        for target_pps in RAMP_STEPS:
            print(f"\n  Step: {target_pps} pps (must hold >= target for {STEP_DURATION}s) ...")
            row = run_step(target_pps=target_pps, baseline_rtt=baseline_rtt)
            rows.append(row)

            avg_cpu = row["avg_cpu_percent"]
            peak_cpu = row["peak_cpu_percent"]
            avg_cpu_str = f"{avg_cpu}%" if avg_cpu is not None else "n/a"
            peak_cpu_str = f"{peak_cpu}%" if peak_cpu is not None else "n/a"
            step_rtt = row["delay_under_attack"]
            step_rtt_avg = f"{step_rtt['avg_ms']}ms" if step_rtt else "n/a"

            if row["reached_and_held"]:
                print(
                    f"  -> avg={row['avg_pi_rate']}/s  peak={row['peak_pi_rate']}/s  "
                    f"avg_cpu={avg_cpu_str}  peak_cpu={peak_cpu_str}  "
                    f"rtt_avg={step_rtt_avg}  reached_in={row['time_to_reach_s']}s  "
                    f"required>={row['required_pi_rate']}/s"
                )
            else:
                print(
                    f"  -> avg={row['avg_pi_rate']}/s  peak={row['peak_pi_rate']}/s  "
                    f"avg_cpu={avg_cpu_str}  peak_cpu={peak_cpu_str}  "
                    f"rtt_avg={step_rtt_avg}  FAILED to hold >= {row['required_pi_rate']}/s "
                    f"within {STEP_TIMEOUT}s"
                )
                print("\nStopping test because target PPS could not be reached and held in time.")
                break

            # Cool-down between steps so the window resets cleanly.
            time.sleep(5)
    finally:
        # Restore mitigation for normal controller operation.
        set_mitigation_enabled(True)

    # Print summary table with RTT columns.
    summary_hdr = (
        f"{'Target PPS':>12}  {'Avg PI Rate':>12}  {'Peak PI Rate':>13}  "
        f"{'Avg CPU %':>10}  {'Peak CPU %':>11}  {'RTT avg':>10}  {'RTT d%':>8}"
    )
    summary_sep = "-" * len(summary_hdr)
    print("\n" + "=" * len(summary_hdr))
    print(summary_hdr)
    print(summary_sep)
    for r in rows:
        avg_cpu = r["avg_cpu_percent"] if r["avg_cpu_percent"] is not None else "n/a"
        peak_cpu = r["peak_cpu_percent"] if r["peak_cpu_percent"] is not None else "n/a"
        step_rtt = r["delay_under_attack"]
        rtt_avg = f"{step_rtt['avg_ms']}ms" if step_rtt else "n/a"
        rtt_delta = _rtt_delta_str(step_rtt, baseline_rtt)
        print(
            f"{r['target_pps']:>12}  {r['avg_pi_rate']:>12}  {r['peak_pi_rate']:>13}  "
            f"{avg_cpu:>10}  {peak_cpu:>11}  {rtt_avg:>10}  {rtt_delta:>8}"
        )
    print("=" * len(summary_hdr))

    # Find where the rate plateaus (controller can't keep up).
    prev_rate = 0
    for r in rows:
        gain = r["avg_pi_rate"] - prev_rate
        if prev_rate > 0 and gain < prev_rate * 0.1:
            print(
                f"\nRate appears to plateau around {r['target_pps']} pps "
                f"(pi_rate gain dropped to {gain:.1f}/s)."
            )
            break
        prev_rate = r["avg_pi_rate"]


if __name__ == "__main__":
    main()
