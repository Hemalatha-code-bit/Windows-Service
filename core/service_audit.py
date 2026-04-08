# core/service_audit.py

import wmi

# -----------------------------------
# Suspicious paths (user-writable locations)
# -----------------------------------
SUSPICIOUS_PATHS = [
    "appdata",
    "temp",
    "downloads",
    "users"
]


# -----------------------------------
# Get all Windows services
# -----------------------------------
def get_all_services():
    c = wmi.WMI()
    services = []

    for service in c.Win32_Service():
        services.append({
            "name": service.Name,
            "display_name": service.DisplayName,
            "state": service.State,
            "start_mode": service.StartMode,
            "path": service.PathName
        })

    return services


# -----------------------------------
# Detect suspicious services
# -----------------------------------
def detect_suspicious_services(services):
    alerts = []

    for service in services:
        name = service.get("name")
        path = (service.get("path") or "").lower()
        start_mode = service.get("start_mode")

        # ❌ Skip normal Windows system paths
        if "windows\\system32" in path:
            continue

        # 🚨 Suspicious path detection
        for sp in SUSPICIOUS_PATHS:
            if sp in path:
                alerts.append(
                    f"Suspicious Service Path: {name} → {service.get('path')}"
                )

        # 🚨 Auto-start service from suspicious location
        if start_mode == "Auto" and any(sp in path for sp in SUSPICIOUS_PATHS):
            alerts.append(
                f"Auto-Start Suspicious Service: {name} → {service.get('path')}"
            )

        # ⚠️ Basic permission risk (user directory execution)
        if "users" in path and "system32" not in path:
            alerts.append(
                f"Potential Weak Permission Service: {name} → {service.get('path')}"
            )

        # ⚠️ Missing path
        if not path:
            alerts.append(f"Service Missing Path: {name}")

    return alerts


# -----------------------------------
# Print sample services
# -----------------------------------
def print_services(services, limit=10):
    print("\n⚙️ Startup Services (Sample):\n")

    for service in services[:limit]:
        print(
            f"{service['name']} | {service['start_mode']} | {service['state']} | {service['path']}"
        )
