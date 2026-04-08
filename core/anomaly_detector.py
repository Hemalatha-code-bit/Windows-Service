# core/anomaly_detector.py

from datetime import datetime
from config import SUSPICIOUS_PARENT_CHILD


def detect_parent_child_anomalies(processes):
    alerts = []

    for pid, proc in processes.items():
        parent_pid = proc.get("ppid")
        parent_proc = processes.get(parent_pid)

        if not parent_proc:
            continue

        parent_name = (parent_proc.get("name") or "").lower()
        child_name = (proc.get("name") or "").lower()

        # Apply detection rules
        if parent_name in SUSPICIOUS_PARENT_CHILD:
            if child_name in SUSPICIOUS_PARENT_CHILD[parent_name]:

                alert = {
                    "timestamp": str(datetime.now()),
                    "alert_type": "Suspicious Parent-Child Relationship",
                    "parent_process": parent_name,
                    "child_process": child_name,
                    "pid": pid,
                    "ppid": parent_pid,
                    "severity": "HIGH"
                }

                alerts.append(alert)

    return alerts
