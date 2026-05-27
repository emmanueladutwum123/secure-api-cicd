from fastapi import FastAPI, Depends, Query, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import Optional

from app.models import SecurityEventCreate, SecurityEventResponse, EventStatsResponse, SeverityLevel
from app.auth import verify_api_key
from app.middleware import SecurityHeadersMiddleware
from app.logger import log_event_created, log_event_resolved, log_event_deleted
from app.database import create_event, get_event, get_all_events, resolve_event, delete_event, get_stats

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Security Events API",
    description=(
        "Secure REST API for managing security events. "
        "Features: API key auth, rate limiting, input validation, "
        "security headers, structured audit logging."
    ),
    version="1.1.0",
)
app.state.limiter = limiter
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


# ---------------------------------------------------------------------------
# Public
# ---------------------------------------------------------------------------

@app.get("/health", tags=["ops"])
async def health_check():
    return {"status": "healthy", "version": "1.1.0"}


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@app.post("/events", response_model=SecurityEventResponse, tags=["events"])
@limiter.limit("30/minute")
async def create_security_event(
    request: Request,
    event: SecurityEventCreate,
    api_key: str = Depends(verify_api_key),
):
    created = create_event(event.model_dump())
    log_event_created(
        event_id=created["id"],
        source_ip=created["source_ip"],
        severity=created["severity"],
        actor_ip=request.client.host if request.client else "unknown",
    )
    return created


@app.get("/events", response_model=list[SecurityEventResponse], tags=["events"])
async def list_events(
    severity: Optional[SeverityLevel] = None,
    resolved: Optional[bool] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    api_key: str = Depends(verify_api_key),
):
    return get_all_events(severity=severity, resolved=resolved, limit=limit, offset=offset)


@app.get("/events/stats", response_model=EventStatsResponse, tags=["events"])
async def event_stats(api_key: str = Depends(verify_api_key)):
    """Aggregate counts by severity and event type."""
    return get_stats()


@app.get("/events/{event_id}", response_model=SecurityEventResponse, tags=["events"])
async def get_single_event(
    event_id: str,
    api_key: str = Depends(verify_api_key),
):
    event = get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.patch("/events/{event_id}/resolve", response_model=SecurityEventResponse, tags=["events"])
async def resolve_security_event(
    request: Request,
    event_id: str,
    api_key: str = Depends(verify_api_key),
):
    event = resolve_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    log_event_resolved(
        event_id=event_id,
        actor_ip=request.client.host if request.client else "unknown",
    )
    return event


@app.delete("/events/{event_id}", tags=["events"])
async def delete_security_event(
    request: Request,
    event_id: str,
    api_key: str = Depends(verify_api_key),
):
    if not delete_event(event_id):
        raise HTTPException(status_code=404, detail="Event not found")
    log_event_deleted(
        event_id=event_id,
        actor_ip=request.client.host if request.client else "unknown",
    )
    return {"detail": "Event deleted"}
