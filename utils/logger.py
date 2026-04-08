# utils/logger.py

def log_alert(alert):
    with open("logs/monitoring.log", "a", encoding="utf-8") as f:
        f.write(str(alert) + "\n")
