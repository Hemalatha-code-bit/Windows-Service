# main.py

import os
from core.process_monitor import get_all_processes, print_process_lineage
from core.anomaly_detector import detect_anomalies
from utils.logger import log_alert


def main():
    print(" Running Parent-Child Monitoring...\n")

    #  Ensure logs folder exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Step 1: Get processes
    processes = get_all_processes()

    # Step 2: Show process lineage
    print_process_lineage(processes)

    # Step 3: Detect anomalies
    alerts = detect_anomalies(processes)

    # Step 4: Print & log results
    print("\n Detection Results:\n")

    if not alerts:
        print(" No suspicious activity detected.")
        return

    for alert in alerts:
        print(alert)
        log_alert(alert)   #  Logging added here


if __name__ == "__main__":
    main()
