# main.py

from core.process_monitor import get_all_processes, print_process_lineage
from core.anomaly_detector import detect_anomalies


def main():
    print("🔍 Running Parent-Child Monitoring...\n")

    # Step 1: Get processes
    processes = get_all_processes()

    # Step 2: Show process lineage
    print_process_lineage(processes)

    # Step 3: Detect anomalies
    alerts = detect_anomalies(processes)

    # Step 4: Print results
    print("\n🔎 Detection Results:\n")

    if not alerts:
        print("✅ No suspicious activity detected.")
        return

    for alert in alerts:
        print(alert)


if __name__ == "__main__":
    main()
