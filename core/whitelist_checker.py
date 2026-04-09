# core/whitelist_checker.py

import json
import os

SUSPICIOUS_PATHS = ["appdata", "temp", "downloads", "users"]


def load_json(file_path):
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r") as f:
        return json.load(f)


def detect_unauthorized_processes(processes):
    alerts = []
    seen = set()

    whitelist = load_json("data/whitelist.json")
    blacklist = load_json("data/blacklist.json")

    for pid, proc in processes.items():
        name = (proc.get("name") or "").lower()
        path = (proc.get("exe") or "").lower()

        if not name:
            continue

        if name in blacklist:
            alert_msg = {
                "alert": f"Blacklisted Process Detected: {name}",
                "pid": pid,
                "path": proc.get("exe"),
                "severity": "HIGH"
            }

        elif whitelist and name not in whitelist and any(sp in path for sp in SUSPICIOUS_PATHS):
            alert_msg = {
                "alert": f"High-Risk Process: {name}",
                "pid": pid,
                "path": proc.get("exe"),
                "severity": "HIGH"
            }

        elif any(sp in path for sp in SUSPICIOUS_PATHS):
            alert_msg = {
                "alert": f"Suspicious Path Process: {name}",
                "pid": pid,
                "path": proc.get("exe"),
                "severity": "MEDIUM"
            }

        else:
            continue

        key = (alert_msg["alert"], alert_msg["pid"], alert_msg["path"])
        if key not in seen:
            alerts.append(alert_msg)
            seen.add(key)

    return alerts
