from datetime import datetime
import uuid

events_db = {}


def create_event(event_data: dict) -> dict:
    event_id = str(uuid.uuid4())[:8]
    event = {
        "id": event_id,
        **event_data,
        "timestamp": datetime.now().isoformat(),
        "resolved": False,
    }
    events_db[event_id] = event
    return event


def get_event(event_id: str) -> dict:
    return events_db.get(event_id)


def get_all_events(severity=None, limit=50):
    events = list(events_db.values())
    if severity:
        events = [e for e in events if e["severity"] == severity]
    return events[:limit]


def resolve_event(event_id: str) -> dict:
    if event_id in events_db:
        events_db[event_id]["resolved"] = True
        return events_db[event_id]
    return None


def delete_event(event_id: str) -> bool:
    if event_id in events_db:
        del events_db[event_id]
        return True
    return False
