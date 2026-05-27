"""
Security headers middleware.

Adds OWASP-recommended response headers to every reply so browsers
enforce safe defaults regardless of which endpoint was hit.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]         = "geolocation=(), microphone=()"
        response.headers["Cache-Control"]              = "no-store"
        # HSTS — 1 year, include subdomains
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Tight CSP: API-only service serves no HTML, so lock everything down
        response.headers["Content-Security-Policy"]   = "default-src 'none'; frame-ancestors 'none'"
        return response
