# main.py

import os
from core.process_monitor import get_all_processes, print_process_lineage
from core.anomaly_detector import detect_anomalies
from core.service_audit import (
    get_all_services,
    detect_suspicious_services,
    print_services
)
from utils.logger import log_alert


def main():
    print("🔍 Running Windows Monitoring Agent...\n")

    # -----------------------------------
    # Ensure logs folder exists
    # -----------------------------------
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # -----------------------------------
    # STEP 1: Process Monitoring
    # -----------------------------------
    processes = get_all_processes()

    print_process_lineage(processes)

    # -----------------------------------
    # STEP 2: Detect Process Anomalies
    # -----------------------------------
    process_alerts = detect_anomalies(processes)

    print("\n🔎 Process Detection Results:\n")

    if not process_alerts:
        print("✅ No suspicious process activity detected.")
    else:
        for alert in process_alerts:
            print(alert)
            log_alert(alert)

    # -----------------------------------
    # STEP 3: Service Audit
    # -----------------------------------
    services = get_all_services()

    print_services(services)

    service_alerts = detect_suspicious_services(services)

    print("\n⚙️ Service Audit Results:\n")

    if not service_alerts:
        print("✅ No suspicious services detected.")
    else:
        for alert in service_alerts:
            print(alert)
            log_alert(alert)

    # -----------------------------------
    # FINAL SUMMARY
    # -----------------------------------
    total_alerts = len(process_alerts) + len(service_alerts)

    print("\n📊 Final Summary:\n")
    print(f"Total Processes Scanned: {len(processes)}")
    print(f"Total Services Scanned: {len(services)}")
    print(f"Total Alerts Generated: {total_alerts}")


if __name__ == "__main__":
    main()
