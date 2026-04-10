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

    # -----------------------------------
    # 1. PROCESS MONITORING
    # -----------------------------------
    processes = get_all_processes()

    # DEMO: Parent first
    processes[1234] = {
        "pid": 1234,
        "ppid": 1,
        "name": "winword.exe",
        "exe": "C:\\Program Files\\Microsoft Office\\winword.exe"
    }

    processes[99998] = {
        "pid": 99998,
        "ppid": 1234,
        "name": "cmd.exe",
        "exe": "C:\\Windows\\System32\\cmd.exe"
    }

    print_process_lineage(processes)
    parent_alerts = detect_anomalies(processes)

    # -----------------------------------
    # 2. SERVICE AUDIT
    # -----------------------------------
    services = get_all_services()

    services.append({
        "name": "TestService",
        "display_name": "Malicious Service",
        "state": "Running",
        "start_mode": "Auto",
        "path": "C:\\Users\\Public\\evil.exe"
    })

    service_alerts = detect_suspicious_services(services)

    # -----------------------------------
    # 3. UNAUTHORIZED PROCESS DETECTION
    # -----------------------------------
    unauthorized_alerts = detect_unauthorized_processes(processes)

    # -----------------------------------
    # COMBINE ALL ALERTS
    # -----------------------------------
    all_alerts = parent_alerts + service_alerts + unauthorized_alerts

    print("\nDetection Results:\n")

    if not all_alerts:
        print("No suspicious activity detected.")
    else:
        for alert in all_alerts:
            print(alert["alert"])
            log_alert(
                alert["alert"],
                pid=alert.get("pid"),
                path=alert.get("path"),
                severity=alert.get("severity")
            )

    # -----------------------------------
    # SUMMARY
    # -----------------------------------
    print("\nSummary:\n")
    print(f"Total Processes: {len(processes)}")
    print(f"Total Services: {len(services)}")
    print(f"Total Alerts: {len(all_alerts)}")


if __name__ == "__main__":
    main()
