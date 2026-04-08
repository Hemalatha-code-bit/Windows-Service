# main.py

import os
from core.service_audit import (
    get_all_services,
    detect_suspicious_services,
    print_services
)
from utils.logger import log_alert


def main():
    print("Running Startup Service Audit...\n")

    # Ensure logs folder exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Clear old logs
    open("logs/monitoring.log", "w").close()

    # -----------------------------------
    # STEP 1: Get all services
    # -----------------------------------
    services = get_all_services()

    # -----------------------------------
    # STEP 2: Print services
    # -----------------------------------
    print_services(services)

    # -----------------------------------
    # STEP 3: Detect suspicious services
    # -----------------------------------
    alerts = detect_suspicious_services(services)

    print("\nService Audit Results:\n")

    if not alerts:
        print("No suspicious services detected.")
    else:
        for alert in alerts:
            print(alert)
            log_alert(alert)

    # -----------------------------------
    # SUMMARY
    # -----------------------------------
    print("\nSummary:\n")
    print(f"Total Services Scanned: {len(services)}")
    print(f"Total Alerts: {len(alerts)}")


if __name__ == "__main__":
    main()
