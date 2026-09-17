# Deployment

The application is a single FastAPI service that also serves the build-free
frontend, so one web service is enough.

## Local
```bash
python -m pip install --user -r requirements.txt
python run.py                      # http://127.0.0.1:8000 (auto-picks free port)
```

## Environment variables
See `.env.example`. Key ones (all optional; safe defaults):

| Variable | Default | Purpose |
|----------|---------|---------|
| `APP_ENV` | development | `production` binds `0.0.0.0` |
| `HOST` / `PORT` | 127.0.0.1 / 8000 | server bind (cloud injects `$PORT`) |
| `DATABASE_PATH` | data/soc.db | SQLite location |
| `DATABASE_URL` | — | `sqlite:///…` honoured; Postgres reserved for future |
| `RESPONSE_SIMULATION` | true | responses always simulated |
| `AUTO_RESPONSE` | false | never auto-execute (legacy `AUTO_RESPONSE_ENABLED` still works) |
| `AUTONOMY_LEVEL_CAP` | 3 | max autonomy (legacy `AUTONOMY_LEVEL` works) |
| `EXTERNAL_TI_ENABLED` | false | external CTI providers not configured |
| `CORS_ORIGINS` | * | comma-separated allowed origins |
| `DATASET_DIR` | data/datasets | where real CIC-IDS CSVs are placed |

## Render.com (or equivalent)
A blueprint is provided in `render.yaml`:
- `startCommand: uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- `healthCheckPath: /health`
- Safe env vars pre-set (`RESPONSE_SIMULATION=true`, `AUTO_RESPONSE=false`).
- A 1 GB disk mounted at `/var/data` with `DATABASE_PATH=/var/data/soc.db`.

A `Procfile` is also included for Heroku-style platforms:
```
web: uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

## Endpoints for health checks
- `/` — serves the SPA (HTTP 200)
- `/health` — `{"status":"ok"}` (HTTP 200)
- `/docs` and `/openapi.json` — FastAPI docs

## Frontend API URLs
All frontend requests use **relative** paths (`/api/...`), so the app works
behind any host/domain without code changes. Verified by
`tests/test_deployment.py::test_frontend_has_no_hardcoded_localhost_api`.

## Database persistence note
SQLite is used by default. **On some cloud platforms local disk is ephemeral**
(reset on redeploy/restart). For persistent storage, attach a disk (as in
`render.yaml`) or migrate to PostgreSQL later. The code centralises DB access in
`backend/database.py`, and `DATABASE_URL` is already read, so a future Postgres
migration is localized to that module.
