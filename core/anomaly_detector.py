# core/anomaly_detector.py

from config import (
    SUSPICIOUS_PARENT_CHILD,
    SUSPICIOUS_CHILD_PROCESSES
)


def detect_anomalies(processes):
    alerts = []

    for pid, proc in processes.items():
        parent = processes.get(proc.get('ppid'))

        if not parent:
            continue

        parent_name = (parent.get('name') or "").lower()
        child_name = (proc.get('name') or "").lower()
        path = proc.get("exe")

        # -----------------------------------
        # ✅ Suspicious Parent-Child (CONFIG BASED)
        # -----------------------------------
        if parent_name in SUSPICIOUS_PARENT_CHILD:
            if child_name in SUSPICIOUS_PARENT_CHILD[parent_name]:
                alerts.append({
                    "alert": f"Suspicious Parent-Child: {parent_name} -> {child_name}",
                    "pid": pid,
                    "path": path,
                    "severity": "HIGH"
                })

        # -----------------------------------
        # ✅ Injection detection
        # -----------------------------------
        if parent_name == "explorer.exe" and child_name in SUSPICIOUS_CHILD_PROCESSES:
            alerts.append({
                "alert": f"Possible Injection: {parent_name} -> {child_name}",
                "pid": pid,
                "path": path,
                "severity": "HIGH"
            })

    return alerts
