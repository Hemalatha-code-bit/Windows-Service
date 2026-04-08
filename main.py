# main.py

from core.process_monitor import get_all_processes
from core.anomaly_detector import detect_parent_child_anomalies
from utils.logger import log_alert


def main():
    print("🔍 Running Parent-Child Monitoring...\n")

    processes = get_all_processes()

    alerts = detect_parent_child_anomalies(processes)

    if not alerts:
        print("✅ No suspicious parent-child activity detected.")
        return

    print("🚨 Suspicious Activities Detected:\n")

    for alert in alerts:
        print(alert)
        log_alert(alert)


if __name__ == "__main__":
    main()
