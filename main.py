# main.py

import os
import shutil
from core.process_monitor import get_all_processes, print_process_lineage
from core.anomaly_detector import detect_anomalies
from utils.logger import log_alert


def clear_cache():
    for root, dirs, files in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d))


def main():
    print("🔍 Running Parent-Child Monitoring...\n")

    # Clear cache
    clear_cache()

    # Ensure logs folder exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Clear old logs
    open("logs/monitoring.log", "w").close()

    processes = get_all_processes()
    print_process_lineage(processes)

    alerts = detect_anomalies(processes)

    print("\n🔎 Detection Results:\n")

    if not alerts:
        print("✅ No suspicious parent-child activity detected.")
    else:
        for alert in alerts:
            print(alert)
            log_alert(alert)


if __name__ == "__main__":
    main()
