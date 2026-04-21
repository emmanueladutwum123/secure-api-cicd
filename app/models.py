from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventCreate(BaseModel):
    source_ip: str = Field(
        ..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    )
    event_type: str = Field(..., min_length=1, max_length=100)
    severity: SeverityLevel
    description: str = Field(..., max_length=500)


class SecurityEventResponse(BaseModel):
    id: str
    source_ip: str
    event_type: str
    severity: SeverityLevel
    description: str
    timestamp: str
    resolved: bool = False
