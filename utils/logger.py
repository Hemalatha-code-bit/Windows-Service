# utils/logger.py

from datetime import datetime
import os


def log_alert(alert):
    log_file = "logs/monitoring.log"

    # Add a blank line ONLY if file already exists and is not empty
    if os.path.exists(log_file) and os.path.getsize(log_file) > 0:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("\n")

    with open(log_file, "a", encoding="utf-8") as f:
        clean_alert = str(alert).strip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {clean_alert}\n")
