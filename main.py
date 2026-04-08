# main.py

import os
from core.process_monitor import get_all_processes, print_process_lineage
from core.anomaly_detector import detect_anomalies
from utils.logger import log_alert


def main():
    print("🔍 Running Parent-Child Monitoring...\n")

    # Ensure logs folder exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Clear old logs
    open("logs/monitoring.log", "w").close()

    # -----------------------------------
    # STEP 1: Get processes
    # -----------------------------------
    processes = get_all_processes()

    # -----------------------------------
    # STEP 2: Show process lineage
    # -----------------------------------
    print_process_lineage(processes)

    # -----------------------------------
    # STEP 3: Detect anomalies
    # -----------------------------------
    alerts = detect_anomalies(processes)

    # -----------------------------------
    # STEP 4: Print & log results
    # -----------------------------------
    print("\n🔎 Detection Results:\n")

    if not alerts:
        print("✅ No suspicious parent-child activity detected.")
    else:
        for alert in alerts:
            print(alert)
            log_alert(alert)


if __name__ == "__main__":
    main()
