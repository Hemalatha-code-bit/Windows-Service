# main.py

from core.process_monitor import get_all_processes, print_process_lineage
from core.anomaly_detector import detect_anomalies


def main():
    print("🔍 Running Parent-Child Monitoring...\n")

    processes = get_all_processes()

    # ✅ Show lineage
    print_process_lineage(processes)

    # ✅ Detect anomalies
    alerts = detect_anomalies(processes)

    print("\n🔎 Detection Results:\n")

    if not alerts:
        print("✅ No suspicious activity detected.")
        return

    for alert in alerts:
        print(alert)


if __name__ == "__main__":
    main()
