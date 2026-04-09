# utils/report_generator.py

import json
import os

REPORT_FILE = "reports/report.json"
FINAL_REPORT = "reports/final_report.txt"


def generate_final_report():
    print("Generating final report...")  # DEBUG

    if not os.path.exists(REPORT_FILE):
        print("No report.json found.")
        return

    try:
        with open(REPORT_FILE, "r") as f:
            content = f.read().strip()

            if not content:
                print("report.json is empty.")
                return

            data = json.loads(content)

    except Exception as e:
        print("Error reading report.json:", e)
        return

    total = len(data)
    high = sum(1 for x in data if x.get("severity") == "HIGH")
    medium = sum(1 for x in data if x.get("severity") == "MEDIUM")

    findings = set(x.get("alert") for x in data)

    os.makedirs("reports", exist_ok=True)

    with open(FINAL_REPORT, "w") as f:
        f.write("===== SECURITY MONITORING REPORT =====\n\n")
        f.write(f"Total Alerts: {total}\n")
        f.write(f"High Severity: {high}\n")
        f.write(f"Medium Severity: {medium}\n\n")

        f.write("Top Findings:\n")
        for item in findings:
            f.write(f"- {item}\n")

    print("Final report generated successfully!")
