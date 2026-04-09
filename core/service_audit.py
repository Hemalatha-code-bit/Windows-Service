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
            alerts.append({
                "alert": f"Service Missing Path: {name}",
                "pid": None,
                "path": None,
                "severity": "MEDIUM"
            })
            continue

        # Normalize quotes
        path = path.replace('"', '')

        # -----------------------------------
        # Unusual non-standard path detection
        # -----------------------------------
        if not any(x in path for x in ["windows", "program files", "program files (x86)"]):
            alerts.append({
                "alert": f"Unusual Service Location: {name}",
                "pid": None,
                "path": raw_path,
                "severity": "MEDIUM"
            })

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
            alerts.append({
                "alert": f"Suspicious Service Path: {name}",
                "pid": None,
                "path": raw_path,
                "severity": "MEDIUM"
            })

        # Auto-start + suspicious path (HIGH)
        if start_mode == "Auto" and any(sp in path for sp in SUSPICIOUS_PATHS):
            alerts.append({
                "alert": f"Auto-Start Suspicious Service: {name}",
                "pid": None,
                "path": raw_path,
                "severity": "HIGH"
            })

        # Permission risk (HIGH)
        if "users" in path:
            alerts.append({
                "alert": f"Potential Weak Permission Service: {name}",
                "pid": None,
                "path": raw_path,
                "severity": "HIGH"
            })

    return alerts


def print_services(services, limit=10):
    print("\nStartup Services (Sample):\n")

    for service in services[:limit]:
        print(
            f"{service['name']} | {service['start_mode']} | {service['state']} | {service['path']}"
        )
