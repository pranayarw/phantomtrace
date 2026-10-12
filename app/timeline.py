
from datetime import datetime, timezone


def build_timeline(events):
    """
    Sort security events chronologically.
    Events with invalid timestamps are reported separately.
    """
    valid_events = []
    invalid_events = []

    for event in events:
        try:
            timestamp = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            valid_events.append((timestamp, event))

        except (ValueError, KeyError, TypeError, AttributeError):
            invalid_events.append({
                "event_id": event.get("event_id", "unknown"),
                "reason": "Missing or invalid timestamp",
            })

    valid_events.sort(key=lambda item: item[0])

    timeline = []

    for timestamp, event in valid_events:
        timeline.append({
            "event_id": event.get("event_id", "unknown"),
            "timestamp": timestamp.isoformat(),
            "event_type": event.get("event_type", "unknown"),
            "source_ip": event.get("source_ip", "unknown"),
            "username": event.get("username"),
        })

    return {
        "events_in_timeline": len(timeline),
        "invalid_events_count": len(invalid_events),
        "timeline": timeline,
        "invalid_events": invalid_events,
    }
