# core/process_monitor.py

import psutil

def get_all_processes():
    processes = {}

    for proc in psutil.process_iter(['pid', 'ppid', 'name']):
        try:
            processes[proc.info['pid']] = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def print_process_lineage(processes, limit=10):
    print("\n Process Lineage (Sample):\n")

    count = 0
    for pid, proc in processes.items():
        parent = processes.get(proc['ppid'])

        if parent:
            print(f"PID: {pid} | Process: {proc['name']} | Parent: {parent['name']} (PPID: {proc['ppid']})")
            count += 1

        if count >= limit:
            break
