    # -----------------------------------
    # STEP 3: Service Audit
    # -----------------------------------
    services = get_all_services()

    print_services(services)

    # ✅ Log sample services (clean + limited)
    for service in services[:10]:
        log_alert(
            f"SERVICE: {service['name']} | {service['start_mode']} | {service['state']} | {service['path']}"
        )

    service_alerts = detect_suspicious_services(services)

    print("\n⚙️ Service Audit Results:\n")

    if not service_alerts:
        print("✅ No suspicious services detected.")
    else:
        for alert in service_alerts:
            print(alert)
            log_alert(alert)
