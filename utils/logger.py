# utils/logger.py

from datetime import datetime


def log_alert(alert):
    with open("logs/monitoring.log", "a", encoding="utf-8") as f:
        clean_alert = str(alert).strip()  # remove extra spaces/newlines
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        f.write(f"[{timestamp}] {clean_alert}\n")
