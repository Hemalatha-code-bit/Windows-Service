# core/process_monitor.py

import psutil

def get_all_processes():
    processes = {}

    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
        try:
            processes[proc.info['pid']] = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes
