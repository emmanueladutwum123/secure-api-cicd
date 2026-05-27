import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import clear_all


@pytest.fixture(autouse=True)
def clean_db():
    """Wipe the in-memory store before every test so tests don't bleed into each other."""
    clear_all()
    yield
    clear_all()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    return {"X-API-Key": "tesla-security-demo-key-2026"}


@pytest.fixture
def sample_event():
    return {
        "source_ip":   "192.168.1.100",
        "event_type":  "brute_force",
        "severity":    "high",
        "description": "Multiple failed login attempts",
    }
