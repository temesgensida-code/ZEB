"""
system_monitor.py - Process and system resource telemetry for load testing.

Monitors:
- Target process tree CPU % (parent + all worker children)
- Target process tree Memory RSS (MB)
- Open File Descriptors count
- Active network connections / sockets count
- Active OS thread count

Outputs:
- Real-time timeseries to CSV
- Terminal summary report on termination
"""

import argparse
import csv
import os
import signal
import sys
import time
from datetime import datetime
import psutil

# Global stop flag
_RUNNING = True


def _handle_signal(sig, frame):
    global _RUNNING
    _RUNNING = False


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


def find_pids_by_port(port: int) -> list[int]:
    """Find process IDs listening on the specified local TCP port."""
    matched_pids = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.pid:
                matched_pids.add(conn.pid)
    except Exception as exc:
        print(f"[system_monitor] Warning: Failed to scan connections by port ({exc})", file=sys.stderr)
    return list(matched_pids)


def get_process_tree(parent_pid: int) -> list[psutil.Process]:
    """Return parent process and all its descendants."""
    procs = []
    try:
        parent = psutil.Process(parent_pid)
        procs.append(parent)
        for child in parent.children(recursive=True):
            procs.append(child)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return procs


def main():
    parser = argparse.ArgumentParser(description="System & Process Telemetry Profiler")
    parser.add_argument("--pid", type=int, default=None, help="Target parent PID to monitor")
    parser.add_argument("--port", type=int, default=8000, help="Target port to discover listening PID")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds (default: 1.0)")
    parser.add_argument("--output", type=str, default=None, help="Output CSV path")
    args = parser.parse_args()

    # Determine output file
    if args.output:
        csv_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        csv_path = os.path.join(reports_dir, f"system_metrics_{timestamp}.csv")

    os.makedirs(os.path.dirname(os.path.abspath(csv_path)), exist_ok=True)

    target_pid = args.pid
    if not target_pid:
        pids = find_pids_by_port(args.port)
        if pids:
            target_pid = pids[0]
            print(f"[system_monitor] Discovered server process listening on port {args.port}: PID {target_pid}")
        else:
            print(f"[system_monitor] Warning: No process listening on port {args.port}. Monitoring full system CPU/Mem.", file=sys.stderr)

    fieldnames = [
        "timestamp",
        "elapsed_sec",
        "system_cpu_pct",
        "proc_cpu_pct",
        "proc_rss_mb",
        "proc_threads",
        "proc_fds",
        "proc_sockets",
        "worker_count",
    ]

    print(f"[system_monitor] Starting resource monitoring (interval={args.interval}s)...")
    print(f"[system_monitor] Logging metrics to: {csv_path}")

    records = []
    start_time = time.time()

    # Prime cpu_percent
    psutil.cpu_percent()
    if target_pid:
        for p in get_process_tree(target_pid):
            try:
                p.cpu_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        f.flush()

        while _RUNNING:
            loop_start = time.time()
            elapsed = round(loop_start - start_time, 2)
            sys_cpu = psutil.cpu_percent()

            proc_cpu = 0.0
            proc_rss = 0.0
            proc_threads = 0
            proc_fds = 0
            proc_sockets = 0
            worker_count = 0

            if target_pid:
                active_procs = get_process_tree(target_pid)
                worker_count = len(active_procs)
                for p in active_procs:
                    try:
                        proc_cpu += p.cpu_percent()
                        proc_rss += p.memory_info().rss / (1024 * 1024)
                        proc_threads += p.num_threads()
                        if hasattr(p, "num_fds"):
                            proc_fds += p.num_fds()
                        conns = p.net_connections(kind="all") if hasattr(p, "net_connections") else p.connections(kind="all")
                        proc_sockets += len(conns)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            row = {
                "timestamp": datetime.now().isoformat(),
                "elapsed_sec": elapsed,
                "system_cpu_pct": round(sys_cpu, 2),
                "proc_cpu_pct": round(proc_cpu, 2),
                "proc_rss_mb": round(proc_rss, 2),
                "proc_threads": proc_threads,
                "proc_fds": proc_fds,
                "proc_sockets": proc_sockets,
                "worker_count": worker_count,
            }
            records.append(row)
            writer.writerow(row)
            f.flush()

            # Dynamic sleep to keep cadence
            sleep_duration = max(0.0, args.interval - (time.time() - loop_start))
            time.sleep(sleep_duration)

    print("\n[system_monitor] Monitoring stopped. Generating summary...")
    if records:
        max_cpu = max(r["proc_cpu_pct"] for r in records)
        avg_cpu = sum(r["proc_cpu_pct"] for r in records) / len(records)
        max_rss = max(r["proc_rss_mb"] for r in records)
        max_fds = max(r["proc_fds"] for r in records)
        max_socks = max(r["proc_sockets"] for r in records)
        max_threads = max(r["proc_threads"] for r in records)

        print("=" * 60)
        print("SYSTEM RESOURCE UTILIZATION SUMMARY")
        print("=" * 60)
        print(f"Total Duration:          {records[-1]['elapsed_sec']} seconds")
        print(f"Peak Process CPU:        {max_cpu:.1f}%")
        print(f"Avg Process CPU:         {avg_cpu:.1f}%")
        print(f"Peak Memory (RSS):       {max_rss:.1f} MB")
        print(f"Peak Open File Descr.:   {max_fds}")
        print(f"Peak Active Sockets:     {max_socks}")
        print(f"Peak Thread Count:       {max_threads}")
        print(f"Metrics CSV saved to:    {csv_path}")
        print("=" * 60)


if __name__ == "__main__":
    main()
