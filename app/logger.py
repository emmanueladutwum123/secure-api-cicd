"""
Structured audit logger.

Every authenticated mutation (create / resolve / delete) is written to
stdout as a JSON line so log aggregators (CloudWatch, Datadog, etc.) can
ingest and alert on it without additional parsing.
"""

import json
import logging
import sys
from datetime import datetime, timezone


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(_handler)
audit_logger.propagate = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event_created(event_id: str, source_ip: str, severity: str, actor_ip: str) -> None:
    audit_logger.info(json.dumps({
        "ts":        _now(),
        "action":    "event.created",
        "event_id":  event_id,
        "source_ip": source_ip,
        "severity":  severity,
        "actor_ip":  actor_ip,
    }))


def log_event_resolved(event_id: str, actor_ip: str) -> None:
    audit_logger.info(json.dumps({
        "ts":       _now(),
        "action":   "event.resolved",
        "event_id": event_id,
        "actor_ip": actor_ip,
    }))


def log_event_deleted(event_id: str, actor_ip: str) -> None:
    audit_logger.info(json.dumps({
        "ts":       _now(),
        "action":   "event.deleted",
        "event_id": event_id,
        "actor_ip": actor_ip,
    }))


def log_auth_failure(actor_ip: str) -> None:
    audit_logger.info(json.dumps({
        "ts":       _now(),
        "action":   "auth.failure",
        "actor_ip": actor_ip,
    }))
