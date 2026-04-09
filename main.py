# main.py

import os
from core.process_monitor import get_all_processes, print_process_lineage
from core.anomaly_detector import detect_anomalies
from core.service_audit import get_all_services, detect_suspicious_services
from core.whitelist_checker import detect_unauthorized_processes
from utils.logger import log_alert


def main():
    print("Running Windows Monitoring Agent...\n")

    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    # Process Monitoring
    processes = get_all_processes()
    print_process_lineage(processes)
    parent_alerts = detect_anomalies(processes)

    # Service Audit
    services = get_all_services()
    service_alerts = detect_suspicious_services(services)

    # Unauthorized Detection
    unauthorized_alerts = detect_unauthorized_processes(processes)

    # Combine
    all_alerts = parent_alerts + service_alerts + unauthorized_alerts

    print("\nDetection Results:\n")

    if not all_alerts:
        print("No suspicious activity detected.")
        return

    for alert in all_alerts:
        print(alert["alert"])
        log_alert(
            alert["alert"],
            pid=alert.get("pid"),
            path=alert.get("path"),
            severity=alert.get("severity")
        )

    print("\nSummary:\n")
    print(f"Total Processes: {len(processes)}")
    print(f"Total Services: {len(services)}")
    print(f"Total Alerts: {len(all_alerts)}")


if __name__ == "__main__":
    main()
