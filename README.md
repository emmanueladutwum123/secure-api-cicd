# Secure FastAPI with CI/CD — Security Events API

A production-style secure REST API built with FastAPI for managing security events, featuring API key authentication, rate limiting, input validation, Docker containerization, and a full GitHub Actions CI/CD pipeline.

## Features

| Feature | Implementation |
|---------|---------------|
| **Authentication** | API key via `X-API-Key` header (`app/auth.py`) |
| **Input validation** | Pydantic models with regex IP validation (`app/models.py`) |
| **Rate limiting** | slowapi — 30 requests/minute per IP |
| **CRUD endpoints** | Create, list, get, resolve, delete security events |
| **CI/CD** | GitHub Actions: tests + linting on every push, Docker build on merge to main |
| **Containerization** | Docker + docker-compose |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (no auth) |
| `POST` | `/events` | Create a security event |
| `GET` | `/events` | List events (filterable by severity) |
| `GET` | `/events/{id}` | Get a single event |
| `PATCH` | `/events/{id}/resolve` | Mark event as resolved |
| `DELETE` | `/events/{id}` | Delete an event |

## Quick Start

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Interactive docs: http://localhost:8000/docs

## Run with Docker

```bash
docker-compose up --build
```

## Run Tests

```bash
pytest tests/ -v
```

## CI/CD Pipeline

`.github/workflows/ci.yml` runs on every push/PR to `main`:

1. **test job** — installs deps, runs `pytest`, runs `flake8` linting
2. **docker job** (main branch only) — builds the Docker image, starts the container, smoke-tests `/health`

## Authentication

Pass your API key in the request header:

```bash
curl -H "X-API-Key: tesla-security-demo-key-2026" \
     -X POST http://localhost:8000/events \
     -H "Content-Type: application/json" \
     -d '{"source_ip":"192.168.1.1","event_type":"brute_force","severity":"high","description":"Multiple failed logins"}'
```

Override the key via env var: `API_KEY=your-key uvicorn app.main:app`
