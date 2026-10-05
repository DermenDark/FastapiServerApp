# Content Sync Storage API

FastAPI backend for the desktop app. This version stores state in PostgreSQL and keeps the same sync endpoints for the client:

- `GET /health`
- `GET /ready`
- `GET /stats`
- `POST /sync/push`
- `POST /sync/pull`
- `POST /sync/meta`
- `POST /sync/status`
- `POST /sync/changes`
- `POST /signal`
- `POST /admin/init-db`
- `POST /admin/vacuum`
- `POST /admin/cleanup`
