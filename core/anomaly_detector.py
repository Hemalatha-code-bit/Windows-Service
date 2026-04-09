# core/anomaly_detector.py

def detect_anomalies(processes):
    alerts = []

    for pid, proc in processes.items():
        parent = processes.get(proc.get('ppid'))
        if not parent:
            continue

        parent_name = (parent.get('name') or "").lower()
        child_name = (proc.get('name') or "").lower()

        if parent_name == "explorer.exe" and child_name == "cmd.exe":
            alerts.append({
                "alert": f"Suspicious Parent-Child: {parent_name} -> {child_name}",
                "pid": pid,
                "path": proc.get("exe"),
                "severity": "HIGH"
            })

    return alerts
