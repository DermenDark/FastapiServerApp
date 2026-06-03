from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, TypeVar

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .db import SnapshotStore, utc_now
from .schemas import (
    HealthResponse,
    MetaResponse,
    ReadyResponse,
    SignalPayload,
    SignalResponse,
    StatsResponse,
    StatusResponse,
    SyncMetaRequest,
    SyncPayload,
    SyncPullRequest,
    SyncResponse,
    UserRef,
)
from .security import extract_client_ip


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("sync_server")
store = SnapshotStore(settings.database_url)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    store.close()


app = FastAPI(
    title="Content Sync Storage API",
    version=settings.server_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def body_size_guard(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH"}:
        body = await request.body()
        if len(body) > settings.max_payload_bytes:
            return JSONResponse(status_code=413, content={"detail": "Payload too large"})
        request._body = body  # type: ignore[attr-defined]
    return await call_next(request)


T = TypeVar("T")


async def _read_json_body(request: Request) -> bytes:
    body = await request.body()
    if not body:
        raise HTTPException(status_code=422, detail="Empty request body")
    return body


def _validate_json(model: type[T], body: bytes) -> T:
    try:
        return model.model_validate_json(body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def _check_health_key(x_sync_key: str) -> None:
    if not settings.allow_public_health and settings.sync_key and x_sync_key.strip() != settings.sync_key:
        raise HTTPException(status_code=401, detail="Invalid sync key")


def _check_sync_key(x_sync_key: str) -> None:
    if settings.sync_key and x_sync_key.strip() != settings.sync_key:
        raise HTTPException(status_code=401, detail="Invalid sync key")


@app.get("/health", response_model=HealthResponse)
def health(x_sync_key: str = Header(default="", alias="X-Sync-Key")) -> dict[str, Any]:
    _check_health_key(x_sync_key)
    return {
        "ok": True,
        "service": "content-sync-storage",
        "time": utc_now(),
        "server_version": settings.server_version,
        "protocol_version": settings.protocol_version,
    }


@app.get("/ready", response_model=ReadyResponse)
def ready(x_sync_key: str = Header(default="", alias="X-Sync-Key")) -> dict[str, Any]:
    _check_health_key(x_sync_key)
    try:
        store.stats()
        return {
            "ok": True,
            "ready": True,
            "database": settings.database_url,
            "server_version": settings.server_version,
            "protocol_version": settings.protocol_version,
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/stats", response_model=StatsResponse)
def stats(x_sync_key: str = Header(default="", alias="X-Sync-Key")) -> dict[str, Any]:
    _check_health_key(x_sync_key)
    return {"ok": True, **store.stats()}


@app.post("/sync/push", response_model=SyncResponse)
async def sync_push(
    request: Request,
    x_sync_key: str = Header(default="", alias="X-Sync-Key"),
    x_user_key: str = Header(default="", alias="X-User-Key"),
    x_request_signature: str = Header(default="", alias="X-Request-Signature"),
    x_request_timestamp: str = Header(default="", alias="X-Request-Timestamp"),
    x_request_nonce: str = Header(default="", alias="X-Request-Nonce"),
    if_match: str = Header(default="", alias="If-Match"),
) -> dict[str, Any]:
    del x_user_key, x_request_signature, x_request_timestamp, x_request_nonce
    _check_sync_key(x_sync_key)
    body = await _read_json_body(request)
    payload = _validate_json(SyncPayload, body)
    auth = store.authorize_request(
        request=request,
        user_id=payload.user_id,
        body=body,
        x_sync_key=x_sync_key.strip(),
        payload_user_key=payload.user_api_key,
    )
    return store.push_snapshot(payload.model_dump(mode="python"), auth, client_ip=extract_client_ip(request), if_match=if_match.strip())


@app.post("/sync/pull", response_model=SyncResponse)
async def sync_pull(
    request: Request,
    x_sync_key: str = Header(default="", alias="X-Sync-Key"),
    x_user_key: str = Header(default="", alias="X-User-Key"),
    x_request_signature: str = Header(default="", alias="X-Request-Signature"),
    x_request_timestamp: str = Header(default="", alias="X-Request-Timestamp"),
    x_request_nonce: str = Header(default="", alias="X-Request-Nonce"),
) -> dict[str, Any]:
    del x_user_key, x_request_signature, x_request_timestamp, x_request_nonce
    _check_sync_key(x_sync_key)
    body = await _read_json_body(request)
    payload = _validate_json(SyncPullRequest, body)
    auth = store.authorize_request(
        request=request,
        user_id=payload.user_id,
        body=body,
        x_sync_key=x_sync_key.strip(),
    )
    return store.pull_snapshot(payload.user_id, auth, client_ip=extract_client_ip(request), since_revision=payload.since_revision, mode=payload.mode)


@app.post("/sync/meta", response_model=MetaResponse)
async def sync_meta(
    request: Request,
    x_sync_key: str = Header(default="", alias="X-Sync-Key"),
    x_user_key: str = Header(default="", alias="X-User-Key"),
    x_request_signature: str = Header(default="", alias="X-Request-Signature"),
    x_request_timestamp: str = Header(default="", alias="X-Request-Timestamp"),
    x_request_nonce: str = Header(default="", alias="X-Request-Nonce"),
) -> dict[str, Any]:
    del x_user_key, x_request_signature, x_request_timestamp, x_request_nonce
    _check_sync_key(x_sync_key)
    body = await _read_json_body(request)
    payload = _validate_json(SyncMetaRequest, body)
    auth = store.authorize_request(request=request, user_id=payload.user_id, body=body, x_sync_key=x_sync_key.strip())
    return store.get_meta(payload.user_id, auth, client_ip=extract_client_ip(request))


@app.post("/sync/status", response_model=StatusResponse)
async def sync_status(
    request: Request,
    x_sync_key: str = Header(default="", alias="X-Sync-Key"),
    x_user_key: str = Header(default="", alias="X-User-Key"),
    x_request_signature: str = Header(default="", alias="X-Request-Signature"),
    x_request_timestamp: str = Header(default="", alias="X-Request-Timestamp"),
    x_request_nonce: str = Header(default="", alias="X-Request-Nonce"),
) -> dict[str, Any]:
    del x_user_key, x_request_signature, x_request_timestamp, x_request_nonce
    _check_sync_key(x_sync_key)
    body = await _read_json_body(request)
    payload = _validate_json(UserRef, body)
    auth = store.authorize_request(request=request, user_id=payload.user_id, body=body, x_sync_key=x_sync_key.strip())
    return store.get_status(payload.user_id, auth, client_ip=extract_client_ip(request))


@app.post("/sync/changes")
async def sync_changes(
    request: Request,
    x_sync_key: str = Header(default="", alias="X-Sync-Key"),
    x_user_key: str = Header(default="", alias="X-User-Key"),
    x_request_signature: str = Header(default="", alias="X-Request-Signature"),
    x_request_timestamp: str = Header(default="", alias="X-Request-Timestamp"),
    x_request_nonce: str = Header(default="", alias="X-Request-Nonce"),
) -> dict[str, Any]:
    del x_user_key, x_request_signature, x_request_timestamp, x_request_nonce
    _check_sync_key(x_sync_key)
    body = await _read_json_body(request)
    payload = _validate_json(SyncPullRequest, body)
    auth = store.authorize_request(request=request, user_id=payload.user_id, body=body, x_sync_key=x_sync_key.strip())
    return store.list_changes(payload.user_id, payload.since_revision, auth, client_ip=extract_client_ip(request))


@app.post("/signal", response_model=SignalResponse)
async def signal(
    request: Request,
    x_sync_key: str = Header(default="", alias="X-Sync-Key"),
    x_user_key: str = Header(default="", alias="X-User-Key"),
    x_request_signature: str = Header(default="", alias="X-Request-Signature"),
    x_request_timestamp: str = Header(default="", alias="X-Request-Timestamp"),
    x_request_nonce: str = Header(default="", alias="X-Request-Nonce"),
) -> dict[str, Any]:
    del x_user_key, x_request_signature, x_request_timestamp, x_request_nonce
    _check_sync_key(x_sync_key)
    body = await _read_json_body(request)
    payload = _validate_json(SignalPayload, body)
    auth = store.authorize_request(request=request, user_id=payload.user_id, body=body, x_sync_key=x_sync_key.strip())
    return store.record_signal(payload.model_dump(mode="python"), auth, client_ip=extract_client_ip(request))


@app.post("/admin/init-db")
def init_db(x_sync_key: str = Header(default="", alias="X-Sync-Key")) -> dict[str, Any]:
    _check_sync_key(x_sync_key)
    return store.init_db()


@app.post("/admin/vacuum")
def vacuum(x_sync_key: str = Header(default="", alias="X-Sync-Key")) -> dict[str, Any]:
    _check_sync_key(x_sync_key)
    return store.vacuum()


@app.post("/admin/cleanup")
def cleanup(x_sync_key: str = Header(default="", alias="X-Sync-Key")) -> dict[str, Any]:
    _check_sync_key(x_sync_key)
    store.cleanup()
    return {"ok": True, "server_version": settings.server_version}
