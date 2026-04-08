# utils/logger.py

def log_alert(alert):
    with open("logs/monitoring.log", "a") as f:
        f.write(str(alert) + "\n")
