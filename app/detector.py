
from collections import defaultdict


def detect_suspicious_logins(events, threshold=5):
    """
    Detect repeated failed logins and preserve supporting evidence.
    An alert indicates suspicious activity, not confirmed compromise.
    """
    failed_events_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type") == "login_failed":
            ip_address = event.get("source_ip", "unknown")
            failed_events_by_ip[ip_address].append(event)

    alerts = []

    for ip_address, failed_events in failed_events_by_ip.items():
        if len(failed_events) >= threshold:
            evidence = [
                {
                    "event_id": event.get("event_id", "unknown"),
                    "timestamp": event.get("timestamp", "unknown"),
                    "event_type": event["event_type"],
                    "source_ip": ip_address,
                }
                for event in failed_events
            ]

            alerts.append({
                "alert_type": "Repeated Failed Logins",
                "source_ip": ip_address,
                "failed_attempts": len(failed_events),
                "severity": "HIGH",
                "confidence": "Rule matched; attack not confirmed",
                "reason": (
                    f"{len(failed_events)} failed login attempts "
                    f"recorded from {ip_address}"
                ),
                "evidence": evidence,
            })

    return alerts


if __name__ == "__main__":
    sample_events = [
        {
            "event_id": f"EVT-{i:03}",
            "timestamp": f"2026-10-11T10:{i:02}:00Z",
            "event_type": "login_failed",
            "source_ip": "192.168.1.50",
        }
        for i in range(1, 6)
    ]

    for alert in detect_suspicious_logins(sample_events):
        print(alert)

