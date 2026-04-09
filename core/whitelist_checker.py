# core/whitelist_checker.py

import json
import os

# Suspicious locations (user-writable)
SUSPICIOUS_PATHS = ["appdata", "temp", "downloads", "users"]


def load_json(file_path):
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r") as f:
        return json.load(f)


def detect_unauthorized_processes(processes):
    alerts = []
    seen = set()  #Prevent duplicate alerts

    whitelist = load_json("data/whitelist.json")
    blacklist = load_json("data/blacklist.json")

    for pid, proc in processes.items():
        name = (proc.get("name") or "").lower()
        path = (proc.get("exe") or "").lower()

        # Skip empty process names
        if not name:
            continue

        # -----------------------------------
        #Blacklist detection (HIGH priority)
        # -----------------------------------
        if name in blacklist:
            alert_msg = f"Blacklisted Process Detected: {name}"
            if alert_msg not in seen:
                alerts.append(alert_msg)
                seen.add(alert_msg)

        # -----------------------------------
        #Unknown + suspicious only
        # -----------------------------------
        elif whitelist and name not in whitelist:
            if any(sp in path for sp in SUSPICIOUS_PATHS):
                alert_msg = f"Unknown Suspicious Process: {name} -> {proc.get('exe')}"
                if alert_msg not in seen:
                    alerts.append(alert_msg)
                    seen.add(alert_msg)

        # -----------------------------------
        #Suspicious path detection
        # -----------------------------------
        if any(sp in path for sp in SUSPICIOUS_PATHS):
            alert_msg = f"Process Running from Suspicious Path: {name} -> {proc.get('exe')}"
            if alert_msg not in seen:
                alerts.append(alert_msg)
                seen.add(alert_msg)

    return alerts
