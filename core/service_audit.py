# core/service_audit.py

import wmi

# Suspicious locations (user-writable)
SUSPICIOUS_PATHS = ["appdata", "temp", "downloads", "users"]


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


def detect_suspicious_services(services):
    alerts = []

    for service in services:
        name = service.get("name")
        raw_path = service.get("path") or ""
        path = raw_path.lower().strip()
        start_mode = service.get("start_mode")

        # Missing or empty path
        if not path:
            alerts.append(f"Service Missing Path: {name}")
            continue

        # Normalize quotes
        path = path.replace('"', '')

        # -----------------------------------
        # ✅ Unusual non-standard path detection
        # -----------------------------------
        if not any(x in path for x in ["windows", "program files", "program files (x86)"]):
            alerts.append(f"Unusual Service Location: {name} → {raw_path}")

        # -----------------------------------
        # Skip trusted Windows directories
        # -----------------------------------
        if any(x in path for x in [
            "windows\\system32",
            "windows\\syswow64",
            "windows\\servicing",
            "microsoft.net"
        ]):
            continue

        # Suspicious path detection
        if any(sp in path for sp in SUSPICIOUS_PATHS):
            alerts.append(f"Suspicious Service Path: {name} → {raw_path}")

        # Auto-start + suspicious path (persistence indicator)
        if start_mode == "Auto" and any(sp in path for sp in SUSPICIOUS_PATHS):
            alerts.append(f"Auto-Start Suspicious Service: {name} → {raw_path}")

        # Permission risk (user-writable directory execution)
        if "users" in path:
            alerts.append(f"Potential Weak Permission Service: {name} → {raw_path}")

    return alerts


def print_services(services, limit=10):
    print("\nStartup Services (Sample):\n")

    for service in services[:limit]:
        print(
            f"{service['name']} | {service['start_mode']} | {service['state']} | {service['path']}"
        )
