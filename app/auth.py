from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader
import os

API_KEY = os.getenv("API_KEY", "tesla-security-demo-key-2026")

api_key_header = APIKeyHeader(name="X-API-Key")


async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key
