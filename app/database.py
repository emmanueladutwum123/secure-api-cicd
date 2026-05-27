from datetime import datetime, timezone
import uuid

events_db: dict[str, dict] = {}


def create_event(event_data: dict) -> dict:
    event_id = str(uuid.uuid4())[:8]
    event = {
        "id":        event_id,
        **event_data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resolved":  False,
    }
    events_db[event_id] = event
    return event


def get_event(event_id: str) -> dict | None:
    return events_db.get(event_id)


def get_all_events(severity=None, resolved: bool | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
    events = list(events_db.values())
    if severity:
        events = [e for e in events if e["severity"] == severity]
    if resolved is not None:
        events = [e for e in events if e["resolved"] is resolved]
    # Newest first
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[offset : offset + limit]


def resolve_event(event_id: str) -> dict | None:
    if event_id in events_db:
        events_db[event_id]["resolved"] = True
        return events_db[event_id]
    return None


def delete_event(event_id: str) -> bool:
    if event_id in events_db:
        del events_db[event_id]
        return True
    return False


def get_stats() -> dict:
    events = list(events_db.values())
    total = len(events)
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    resolved_count = 0

    for e in events:
        sev = e["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        etype = e["event_type"]
        by_type[etype] = by_type.get(etype, 0) + 1
        if e["resolved"]:
            resolved_count += 1

    return {
        "total":          total,
        "resolved":       resolved_count,
        "open":           total - resolved_count,
        "by_severity":    by_severity,
        "by_event_type":  by_type,
    }


def clear_all() -> None:
    """Test helper — wipes the in-memory store."""
    events_db.clear()
