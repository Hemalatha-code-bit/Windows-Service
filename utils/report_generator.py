# utils/report_generator.py

import json
import os

REPORT_FILE = "reports/report.json"
FINAL_REPORT = "reports/final_report.txt"


def generate_final_report():
    if not os.path.exists(REPORT_FILE):
        print("No report.json found.")
        return

    with open(REPORT_FILE, "r") as f:
        try:
            data = json.load(f)
        except:
            print("Invalid JSON report.")
            return

    total = len(data)
    high = sum(1 for x in data if x["severity"] == "HIGH")
    medium = sum(1 for x in data if x["severity"] == "MEDIUM")

    findings = set()
    for entry in data:
        findings.add(entry["alert"])

    os.makedirs("reports", exist_ok=True)

    with open(FINAL_REPORT, "w") as f:
        f.write("===== SECURITY MONITORING REPORT =====\n\n")
        f.write(f"Total Alerts: {total}\n")
        f.write(f"High Severity: {high}\n")
        f.write(f"Medium Severity: {medium}\n\n")

        f.write("Top Findings:\n")
        for item in findings:
            f.write(f"- {item}\n")

    print("Final report generated: reports/final_report.txt")
