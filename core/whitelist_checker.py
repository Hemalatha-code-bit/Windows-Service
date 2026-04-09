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

        # Blacklist (highest priority)
        if name in blacklist:
            alert_msg = f"Blacklisted Process Detected: {name}"
        
        # Unknown + suspicious = HIGH RISK
        elif whitelist and name not in whitelist and any(sp in path for sp in SUSPICIOUS_PATHS):
            alert_msg = f"High-Risk Process: {name} -> {proc.get('exe')}"
        
        # Only suspicious path
        elif any(sp in path for sp in SUSPICIOUS_PATHS):
            alert_msg = f"Suspicious Path Process: {name} -> {proc.get('exe')}"
        
        else:
            continue

        # جلوگیری duplicate alerts
        if alert_msg not in seen:
            alerts.append(alert_msg)
            seen.add(alert_msg)

    return alerts
