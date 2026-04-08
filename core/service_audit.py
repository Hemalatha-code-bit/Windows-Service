# core/service_audit.py

import wmi
import os

# -----------------------------------
# Suspicious paths (common malware locations)
# -----------------------------------
SUSPICIOUS_PATHS = ["temp", "appdata", "downloads"]

# Baseline file
BASELINE_FILE = "data/services_baseline.txt"

# Known safe system services (to reduce false positives)
KNOWN_SYSTEM_SERVICES = ["LSM", "NetSetupSvc"]


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
# Save baseline (first run)
# -----------------------------------
def save_baseline(services):
    if not os.path.exists("data"):
        os.makedirs("data")

    with open(BASELINE_FILE, "w") as f:
        for service in services:
            f.write(service["name"] + "\n")


# -----------------------------------
# Load baseline
# -----------------------------------
def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return []

    with open(BASELINE_FILE, "r") as f:
        return [line.strip() for line in f.readlines()]


# -----------------------------------
# Detect suspicious services
# -----------------------------------
def detect_suspicious_services(services):
    alerts = []

    baseline = load_baseline()

    for service in services:
        name = service.get("name")
        path = (service.get("path") or "").lower()
        start_mode = service.get("start_mode")

        # -----------------------------------
        # 1. Suspicious path detection
        # -----------------------------------
        for sp in SUSPICIOUS_PATHS:
            if sp in path:
                alerts.append(
                    f"Suspicious Service Path: {name} → {service.get('path')}"
                )

        # -----------------------------------
        # 2. Auto-start suspicious service
        # -----------------------------------
        if start_mode == "Auto" and any(sp in path for sp in SUSPICIOUS_PATHS):
            alerts.append(
                f"Auto-Start Suspicious Service: {name} → {service.get('path')}"
            )

        # -----------------------------------
        # 3. Missing path (skip known system)
        # -----------------------------------
        if not path and name not in KNOWN_SYSTEM_SERVICES:
            alerts.append(f"Service Missing Path: {name}")

        # -----------------------------------
        # 4. New service detection
        # -----------------------------------
        if baseline and name not in baseline:
            alerts.append(f"New Service Detected: {name}")

        # -----------------------------------
        # 5. Basic permission misconfiguration
        # -----------------------------------
        if path and not path.startswith("c:\\windows\\system32"):
            alerts.append(
                f"Service running outside system directory: {name} → {service.get('path')}"
            )

    # -----------------------------------
    # Save baseline if not exists
    # -----------------------------------
    if not baseline:
        save_baseline(services)

    return alerts


# -----------------------------------
# Print services (for demo)
# -----------------------------------
def print_services(services, limit=10):
    print("\n⚙️ Startup Services (Sample):\n")

    for service in services[:limit]:
        print(
            f"{service['name']} | {service['start_mode']} | {service['state']} | {service['path']}"
        )
