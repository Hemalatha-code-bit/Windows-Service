# main.py

import os
from core.process_monitor import get_all_processes
from core.whitelist_checker import detect_unauthorized_processes
from utils.logger import log_alert


def main():
    print("Running Unauthorized Process Detection...\n")

    # Ensure logs folder exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # STEP 1: Get processes
    processes = get_all_processes()

    # -----------------------------------
    # TEST DATA (for demo)
    # -----------------------------------
    processes[99999] = {
        "pid": 99999,
        "ppid": 1234,
        "name": "malware.exe",
        "exe": "C:\\Users\\Public\\malware.exe"
    }

    # STEP 2: Detect unauthorized processes
    alerts = detect_unauthorized_processes(processes)

    print("Unauthorized Process Detection Results:\n")

    if not alerts:
        print("No unauthorized processes detected.")
    else:
        for alert in alerts:
            print(alert)
            log_alert(alert)

    print("\nSummary:\n")
    print(f"Total Processes Scanned: {len(processes)}")
    print(f"Total Alerts: {len(alerts)}")


if __name__ == "__main__":
    main()
