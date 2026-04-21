import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
API_KEY = "tesla-security-demo-key-2026"
HEADERS = {"X-API-Key": API_KEY}


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_create_event():
    event = {
        "source_ip": "192.168.1.100",
        "event_type": "brute_force_attempt",
        "severity": "high",
        "description": "Multiple failed logins detected",
    }
    response = client.post("/events", json=event, headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["severity"] == "high"
    assert data["resolved"] is False
    assert "id" in data


def test_create_event_no_auth():
    event = {
        "source_ip": "10.0.0.1",
        "event_type": "port_scan",
        "severity": "medium",
        "description": "Suspicious port scanning activity",
    }
    response = client.post("/events", json=event)
    assert response.status_code == 401


def test_create_event_invalid_ip():
    event = {
        "source_ip": "not_an_ip",
        "event_type": "test",
        "severity": "low",
        "description": "Test event",
    }
    response = client.post("/events", json=event, headers=HEADERS)
    assert response.status_code == 422


def test_list_events():
    response = client.get("/events", headers=HEADERS)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_filter_by_severity():
    response = client.get("/events?severity=high", headers=HEADERS)
    assert response.status_code == 200
    events = response.json()
    for event in events:
        assert event["severity"] == "high"


def test_resolve_event():
    event = {
        "source_ip": "172.16.0.1",
        "event_type": "malware_detected",
        "severity": "critical",
        "description": "Malware signature match on endpoint",
    }
    create_resp = client.post("/events", json=event, headers=HEADERS)
    event_id = create_resp.json()["id"]

    resolve_resp = client.patch(f"/events/{event_id}/resolve", headers=HEADERS)
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["resolved"] is True


def test_delete_event():
    event = {
        "source_ip": "10.10.10.10",
        "event_type": "test_event",
        "severity": "low",
        "description": "Event to be deleted",
    }
    create_resp = client.post("/events", json=event, headers=HEADERS)
    event_id = create_resp.json()["id"]

    delete_resp = client.delete(f"/events/{event_id}", headers=HEADERS)
    assert delete_resp.status_code == 200

    get_resp = client.get(f"/events/{event_id}", headers=HEADERS)
    assert get_resp.status_code == 404


def test_get_nonexistent_event():
    response = client.get("/events/doesnotexist", headers=HEADERS)
    assert response.status_code == 404
