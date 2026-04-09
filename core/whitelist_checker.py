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
    seen = set()  # ✅ Track processed PIDs

    whitelist = load_json("data/whitelist.json")
    blacklist = load_json("data/blacklist.json")

    for pid, proc in processes.items():
        name = (proc.get("name") or "").lower()
        path = (proc.get("exe") or "").lower()

        if not name:
            continue

        # -----------------------------------
        # 🚨 Blacklist (HIGH priority)
        # -----------------------------------
        if name in blacklist:
            alert_msg = {
                "alert": f"Blacklisted Process Detected: {name}",
                "pid": pid,
                "path": proc.get("exe"),
                "severity": "HIGH"
            }

        # -----------------------------------
        # 🚨 High-Risk (unknown + suspicious)
        # -----------------------------------
        elif whitelist and name not in whitelist and any(sp in path for sp in SUSPICIOUS_PATHS):
            alert_msg = {
                "alert": f"High-Risk Process: {name}",
                "pid": pid,
                "path": proc.get("exe"),
                "severity": "HIGH"
            }

        # -----------------------------------
        # ⚠️ Suspicious path only
        # -----------------------------------
        elif any(sp in path for sp in SUSPICIOUS_PATHS):
            alert_msg = {
                "alert": f"Suspicious Path Process: {name}",
                "pid": pid,
                "path": proc.get("exe"),
                "severity": "MEDIUM"
            }

        else:
            continue

        # -----------------------------------
        # ✅ FIX: Deduplicate by PID
        # -----------------------------------
        if pid not in seen:
            alerts.append(alert_msg)
            seen.add(pid)

    return alerts
