"""
API test suite — uses fixtures from conftest.py for isolation.
Each test gets a clean in-memory database (autouse fixture).
"""


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health_check(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "max-age=" in r.headers["strict-transport-security"]
    assert r.headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def test_create_event_no_auth(client, sample_event):
    assert client.post("/events", json=sample_event).status_code == 401


def test_create_event_wrong_key(client, sample_event):
    assert client.post("/events", json=sample_event, headers={"X-API-Key": "wrong"}).status_code == 403


def test_list_events_no_auth(client):
    assert client.get("/events").status_code == 401


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def test_create_event(client, auth_headers, sample_event):
    r = client.post("/events", json=sample_event, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["severity"] == "high"
    assert data["resolved"] is False
    assert "id" in data
    assert "timestamp" in data


def test_create_event_invalid_ip(client, auth_headers):
    bad = {"source_ip": "not_an_ip", "event_type": "test", "severity": "low", "description": "x"}
    assert client.post("/events", json=bad, headers=auth_headers).status_code == 422


def test_create_event_description_too_long(client, auth_headers):
    bad = {"source_ip": "1.2.3.4", "event_type": "test", "severity": "low", "description": "x" * 501}
    assert client.post("/events", json=bad, headers=auth_headers).status_code == 422


def test_create_event_invalid_severity(client, auth_headers):
    bad = {"source_ip": "1.2.3.4", "event_type": "test", "severity": "ultra", "description": "x"}
    assert client.post("/events", json=bad, headers=auth_headers).status_code == 422


# ---------------------------------------------------------------------------
# List + filter + pagination
# ---------------------------------------------------------------------------

def test_list_events_empty(client, auth_headers):
    r = client.get("/events", headers=auth_headers)
    assert r.status_code == 200
    assert r.json() == []


def test_list_events(client, auth_headers, sample_event):
    client.post("/events", json=sample_event, headers=auth_headers)
    r = client.get("/events", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_filter_by_severity(client, auth_headers):
    client.post("/events", json={**{"source_ip": "1.1.1.1", "event_type": "t", "description": "d"}, "severity": "high"}, headers=auth_headers)
    client.post("/events", json={**{"source_ip": "1.1.1.2", "event_type": "t", "description": "d"}, "severity": "low"}, headers=auth_headers)
    r = client.get("/events?severity=high", headers=auth_headers)
    assert r.status_code == 200
    for e in r.json():
        assert e["severity"] == "high"


def test_filter_by_resolved(client, auth_headers, sample_event):
    create_r = client.post("/events", json=sample_event, headers=auth_headers)
    eid = create_r.json()["id"]
    client.patch(f"/events/{eid}/resolve", headers=auth_headers)

    open_events = client.get("/events?resolved=false", headers=auth_headers).json()
    resolved_events = client.get("/events?resolved=true", headers=auth_headers).json()
    assert all(not e["resolved"] for e in open_events)
    assert all(e["resolved"] for e in resolved_events)


def test_pagination(client, auth_headers):
    base = {"source_ip": "1.2.3.4", "event_type": "scan", "severity": "low", "description": "x"}
    for _ in range(5):
        client.post("/events", json=base, headers=auth_headers)

    page1 = client.get("/events?limit=3&offset=0", headers=auth_headers).json()
    page2 = client.get("/events?limit=3&offset=3", headers=auth_headers).json()
    assert len(page1) == 3
    assert len(page2) == 2
    ids1 = {e["id"] for e in page1}
    ids2 = {e["id"] for e in page2}
    assert ids1.isdisjoint(ids2)


# ---------------------------------------------------------------------------
# Get single
# ---------------------------------------------------------------------------

def test_get_single_event(client, auth_headers, sample_event):
    eid = client.post("/events", json=sample_event, headers=auth_headers).json()["id"]
    r = client.get(f"/events/{eid}", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["id"] == eid


def test_get_nonexistent_event(client, auth_headers):
    assert client.get("/events/doesnotexist", headers=auth_headers).status_code == 404


# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------

def test_resolve_event(client, auth_headers, sample_event):
    eid = client.post("/events", json=sample_event, headers=auth_headers).json()["id"]
    r = client.patch(f"/events/{eid}/resolve", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["resolved"] is True


def test_resolve_nonexistent(client, auth_headers):
    assert client.patch("/events/nope/resolve", headers=auth_headers).status_code == 404


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def test_delete_event(client, auth_headers, sample_event):
    eid = client.post("/events", json=sample_event, headers=auth_headers).json()["id"]
    assert client.delete(f"/events/{eid}", headers=auth_headers).status_code == 200
    assert client.get(f"/events/{eid}", headers=auth_headers).status_code == 404


def test_delete_nonexistent(client, auth_headers):
    assert client.delete("/events/nope", headers=auth_headers).status_code == 404


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_stats_empty(client, auth_headers):
    r = client.get("/events/stats", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["open"] == 0
    assert data["resolved"] == 0


def test_stats_counts(client, auth_headers):
    events = [
        {"source_ip": "1.1.1.1", "event_type": "brute_force", "severity": "high",     "description": "x"},
        {"source_ip": "1.1.1.2", "event_type": "port_scan",   "severity": "medium",   "description": "x"},
        {"source_ip": "1.1.1.3", "event_type": "brute_force", "severity": "critical",  "description": "x"},
    ]
    ids = [client.post("/events", json=e, headers=auth_headers).json()["id"] for e in events]
    client.patch(f"/events/{ids[0]}/resolve", headers=auth_headers)

    stats = client.get("/events/stats", headers=auth_headers).json()
    assert stats["total"] == 3
    assert stats["resolved"] == 1
    assert stats["open"] == 2
    assert stats["by_severity"]["high"] == 1
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_event_type"]["brute_force"] == 2
