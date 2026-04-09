# utils/logger.py

from datetime import datetime
import json
import os

LOG_FILE = "logs/monitoring.log"
REPORT_FILE = "reports/report.json"


def log_alert(alert, pid=None, path=None, severity="MEDIUM"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = {
        "timestamp": timestamp,
        "alert": alert,
        "pid": pid,
        "path": path,
        "severity": severity
    }

    # Ensure folders exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    # Write readable log
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{severity}] {alert} | PID={pid} | PATH={path}\n")

    # Append to JSON report
    if os.path.exists(REPORT_FILE):
        with open(REPORT_FILE, "r") as f:
            data = json.load(f)
    else:
        data = []

    data.append(log_entry)

    with open(REPORT_FILE, "w") as f:
        json.dump(data, f, indent=4)
