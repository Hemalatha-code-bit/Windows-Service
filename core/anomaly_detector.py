# core/anomaly_detector.py

from config import SUSPICIOUS_PARENT_CHILD


def detect_anomalies(processes):
    alerts = []

    for pid, proc in processes.items():
        parent = processes.get(proc['ppid'])

        if not parent:
            continue

        parent_name = parent['name'].lower()
        child_name = proc['name'].lower()

        # 🚨 Suspicious Parent-Child
        if parent_name in SUSPICIOUS_PARENT_CHILD:
            if child_name in SUSPICIOUS_PARENT_CHILD[parent_name]:
                alerts.append(f"🚨 Suspicious Parent-Child: {parent_name} → {child_name}")

        # ⚠️ Suspicious Chain (Grandparent → Parent → Child)
        grandparent = processes.get(parent['ppid'])
        if grandparent:
            chain = f"{grandparent['name']} → {parent_name} → {child_name}"

            if "winword.exe" in chain and "powershell.exe" in chain:
                alerts.append(f"⚠️ Suspicious Process Chain: {chain}")

        # ⚠️ Injection Indicator (basic heuristic)
        if parent_name == "explorer.exe" and child_name not in ["chrome.exe", "msedge.exe"]:
            alerts.append(f"⚠️ Possible Injection: {parent_name} → {child_name}")

    return alerts
