# utils/report_generator.py

import json
import os

REPORT_FILE = "reports/report.json"
FINAL_REPORT = "reports/final_report.txt"


def generate_final_report():
    print("Generating final report...")

    os.makedirs("reports", exist_ok=True)

    # Check if report.json exists
    if not os.path.exists(REPORT_FILE):
        with open(FINAL_REPORT, "w", encoding="utf-8") as f:
            f.write("No report.json found.\n")
        print("Final report created (no data).")
        return

    # Read JSON safely
    try:
        with open(REPORT_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()

            if not content:
                with open(FINAL_REPORT, "w", encoding="utf-8") as f2:
                    f2.write("No alerts found.\n")
                print("Final report created (empty data).")
                return

            data = json.loads(content)

    except Exception as e:
        with open(FINAL_REPORT, "w", encoding="utf-8") as f:
            f.write(f"Error reading report.json: {e}\n")
        print("Final report created (error case).")
        return

    # Process data
    total = len(data)
    high = sum(1 for x in data if x.get("severity") == "HIGH")
    medium = sum(1 for x in data if x.get("severity") == "MEDIUM")

    print("Total alerts loaded:", total)  # DEBUG

    # Safe findings extraction
    findings = set()
    for x in data:
        alert = x.get("alert")
        if alert:
            findings.add(alert)

    # Write final report (FIXED)
    with open(FINAL_REPORT, "w", encoding="utf-8") as f:
        f.write("===== SECURITY MONITORING REPORT =====\n\n")
        f.write(f"Total Alerts: {total}\n")
        f.write(f"High Severity: {high}\n")
        f.write(f"Medium Severity: {medium}\n\n")

        f.write("Top Findings:\n")
        for item in findings:
            f.write("- " + str(item) + "\n")

        f.write("\n--- End of Report ---\n")

    print("Final report successfully generated!")
