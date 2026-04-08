# utils/logger.py

from datetime import datetime


def log_alert(alert):
    log_file = "logs/monitoring.log"

    with open(log_file, "a", encoding="utf-8") as f:
        clean_alert = str(alert).strip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {clean_alert}\n")
