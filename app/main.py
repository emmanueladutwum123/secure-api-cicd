from fastapi import FastAPI, Depends, Query, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from typing import Optional, List

from app.models import SecurityEventCreate, SecurityEventResponse, SeverityLevel
from app.auth import verify_api_key
from app.database import create_event, get_event, get_all_events, resolve_event, delete_event

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Security Events API",
    description=(
        "Secure REST API for managing security events with "
        "authentication, rate limiting, and input validation."
    ),
    version="1.0.0",
)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}


@app.post("/events", response_model=SecurityEventResponse)
@limiter.limit("30/minute")
async def create_security_event(
    request: Request,
    event: SecurityEventCreate,
    api_key: str = Depends(verify_api_key),
):
    return create_event(event.model_dump())


@app.get("/events", response_model=List[SecurityEventResponse])
async def list_events(
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(default=50, le=200),
    api_key: str = Depends(verify_api_key),
):
    return get_all_events(severity=severity, limit=limit)


@app.get("/events/{event_id}", response_model=SecurityEventResponse)
async def get_single_event(
    event_id: str,
    api_key: str = Depends(verify_api_key),
):
    event = get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.patch("/events/{event_id}/resolve", response_model=SecurityEventResponse)
async def resolve_security_event(
    event_id: str,
    api_key: str = Depends(verify_api_key),
):
    event = resolve_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.delete("/events/{event_id}")
async def delete_security_event(
    event_id: str,
    api_key: str = Depends(verify_api_key),
):
    if delete_event(event_id):
        return {"detail": "Event deleted"}
    raise HTTPException(status_code=404, detail="Event not found")
