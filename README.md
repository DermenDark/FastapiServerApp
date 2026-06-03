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

## Local run with Docker

1. Copy the environment file:
   ```bash
   cp .env.example .env
   ```

2. Set `SYNC_KEY` to a long secret.

3. Start the stack:
   ```bash
   docker compose up -d --build
   ```

4. Check the API:
   ```bash
   curl http://localhost:8000/health
   curl http://localhost:8000/ready
   curl http://localhost:8000/stats
   ```

## Railway deployment

Use one Railway project with two services:

1. PostgreSQL service.
2. Web service for this FastAPI app.

Set the web service variables:

- `DATABASE_URL` — Railway will expose this from the PostgreSQL service.
- `SYNC_KEY` — same secret as in the desktop client.
- optionally `ALLOW_PUBLIC_HEALTH=true`.

Use this start command when you deploy from source:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

If you deploy with Docker, the included `Dockerfile` already runs that command.

## Client settings

In the desktop app set:

- API base URL: the Railway domain, for example `https://your-app.up.railway.app`
- Sync key: the same `SYNC_KEY`

The desktop client already sends `X-Sync-Key`, so no client rewrite is needed.

## Notes

- PostgreSQL is a better fit than SQLite for concurrent users and remote hosting.
- The server auto-creates tables on startup.
- `sync/pull` falls back to a full snapshot when a true delta is not available.
