
from app.detector import detect_suspicious_logins


def make_events(count, event_type="login_failed"):
    return [
        {
            "event_id": f"EVT-{i:03}",
            "timestamp": f"2026-10-11T10:{i:02}:00Z",
            "event_type": event_type,
            "source_ip": "192.168.1.50",
        }
        for i in range(1, count + 1)
    ]


def test_five_failed_logins_generate_alert():
    events = make_events(5)

    alerts = detect_suspicious_logins(events)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["severity"] == "HIGH"
    assert len(alerts[0]["evidence"]) == 5


def test_four_failed_logins_do_not_generate_alert():
    events = make_events(4)

    alerts = detect_suspicious_logins(events)

    assert alerts == []


def test_successful_logins_do_not_generate_alert():
    events = make_events(6, event_type="login_success")

    alerts = detect_suspicious_logins(events)

    assert alerts == []
