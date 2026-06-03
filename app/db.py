from __future__ import annotations

import json
import logging
import threading
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import settings
from .security import RequestAuth, canonical_string, enforce_rate_limit, extract_client_ip, nonce_cache, sha256_hex, sha256_hex_bytes, sign_request, verify_signature


logger = logging.getLogger("sync_server")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def canonical_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)


def _db_json(value: Any) -> str:
    return canonical_json(value if value is not None else {})


def _payload_size(value: Any) -> tuple[int, int]:
    raw = canonical_json(value).encode("utf-8")
    return len(raw), len(zlib.compress(raw, level=9))


@dataclass(slots=True)
class SnapshotRow:
    user_id: str
    revision: int
    schema_version: int
    payload_json: dict[str, Any]
    payload_hash: str
    payload_size: int
    compressed_size: int
    etag: str
    updated_at: str
    created_at: str


class SnapshotStore:
    def __init__(self, database_url: str | None = None) -> None:
        self.dsn = (database_url or settings.database_url).strip()
        if not self.dsn:
            raise RuntimeError("DATABASE_URL is required")
        self.lock = threading.RLock()
        self.pool = ConnectionPool(
            conninfo=self.dsn,
            min_size=1,
            max_size=5,
            kwargs={"autocommit": True, "row_factory": dict_row},
            open=True,
        )
        self.init_schema()

    @contextmanager
    def _conn(self):
        with self.pool.connection() as conn:
            yield conn

    def close(self) -> None:
        self.pool.close()

    def init_schema(self) -> dict[str, Any]:
        ddl = """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL DEFAULT '',
            api_key_hash TEXT NOT NULL DEFAULT '',
            protocol_version TEXT NOT NULL DEFAULT '',
            last_nonce TEXT NOT NULL DEFAULT '',
            last_client_ip TEXT NOT NULL DEFAULT '',
            reserved_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_signal_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL DEFAULT 0,
            schema_version INTEGER NOT NULL DEFAULT 1,
            payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            payload_hash TEXT NOT NULL DEFAULT '',
            payload_size INTEGER NOT NULL DEFAULT 0,
            compressed_size INTEGER NOT NULL DEFAULT 0,
            etag TEXT NOT NULL DEFAULT '',
            reserved_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS snapshot_history (
            id BIGSERIAL PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1,
            payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            payload_hash TEXT NOT NULL DEFAULT '',
            payload_size INTEGER NOT NULL DEFAULT 0,
            compressed_size INTEGER NOT NULL DEFAULT 0,
            etag TEXT NOT NULL DEFAULT '',
            reserved_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_snapshot_history_user_revision ON snapshot_history(user_id, revision DESC);
        CREATE INDEX IF NOT EXISTS idx_snapshot_history_created_at ON snapshot_history(created_at DESC);

        CREATE TABLE IF NOT EXISTS signals (
            id BIGSERIAL PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            signal_type TEXT NOT NULL DEFAULT 'ping',
            message TEXT NOT NULL DEFAULT '',
            base_revision INTEGER NOT NULL DEFAULT 0,
            payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            status TEXT NOT NULL DEFAULT 'pending',
            expires_at TIMESTAMPTZ NOT NULL,
            reserved_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_signals_user_status ON signals(user_id, status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_signals_expires_at ON signals(expires_at);

        CREATE TABLE IF NOT EXISTS audit_log (
            id BIGSERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT '',
            client_ip TEXT NOT NULL DEFAULT '',
            status_code INTEGER NOT NULL DEFAULT 0,
            payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            secret_hash TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id, created_at DESC);
        """
        with self._conn() as conn:
            with conn.transaction():
                conn.execute(ddl)
        return {"ok": True, "database": self.dsn, "schema": "initialized", "server_version": settings.server_version}

    def _log_audit(self, event_type: str, user_id: str, client_ip: str, status_code: int, payload: dict[str, Any], secret_hash: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_log(event_type, user_id, client_ip, status_code, payload_json, secret_hash)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s)
                """,
                (event_type, user_id, client_ip, status_code, _db_json(payload), secret_hash),
            )

    def _get_snapshot_row(self, user_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM snapshots WHERE user_id = %s", (user_id,)).fetchone()
            return dict(row) if row else None

    def _get_history_row(self, user_id: str, revision: int) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM snapshot_history WHERE user_id = %s AND revision = %s ORDER BY id DESC LIMIT 1",
                (user_id, revision),
            ).fetchone()
            return dict(row) if row else None

    def _count(self, table: str) -> int:
        with self._conn() as conn:
            row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
            return int((row or {}).get("c", 0))

    def _signal_count(self, user_id: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM signals WHERE user_id = %s AND status = 'pending' AND expires_at > NOW()",
                (user_id,),
            ).fetchone()
            return int((row or {}).get("c", 0))

    def _history_count(self, user_id: str) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM snapshot_history WHERE user_id = %s", (user_id,)).fetchone()
            return int((row or {}).get("c", 0))

    def ensure_user(self, user_id: str, *, username: str = "", client_ip: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO users(id, username, last_client_ip, last_seen_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    username = CASE WHEN EXCLUDED.username <> '' THEN EXCLUDED.username ELSE users.username END,
                    last_client_ip = CASE WHEN EXCLUDED.last_client_ip <> '' THEN EXCLUDED.last_client_ip ELSE users.last_client_ip END,
                    last_seen_at = NOW(),
                    updated_at = NOW()
                """,
                (user_id, username or "", client_ip or ""),
            )

    def authorize_request(
        self,
        *,
        request,
        user_id: str,
        body: bytes,
        x_sync_key: str = "",
        x_user_key: str = "",
        x_request_signature: str = "",
        x_request_timestamp: str = "",
        x_request_nonce: str = "",
        payload_user_key: str = "",
    ) -> RequestAuth:
        del request, body, x_user_key, x_request_signature, x_request_timestamp, x_request_nonce, payload_user_key
        if settings.sync_key:
            if x_sync_key.strip() != settings.sync_key:
                raise HTTPException(status_code=401, detail="Invalid sync key")
            secret = settings.sync_key
            secret_kind = "sync_key"
        else:
            secret = ""
            secret_kind = "anonymous"
        self.ensure_user(user_id)
        return RequestAuth(user_id=user_id, secret=secret, secret_kind=secret_kind, signed=False)

    def _current_snapshot_doc(self, row: dict[str, Any]) -> dict[str, Any]:
        payload = row.get("payload_json") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        result = dict(payload) if isinstance(payload, dict) else {}
        result.setdefault("user_id", row.get("user_id") or "")
        result.setdefault("schema_version", int(row.get("schema_version") or result.get("schema_version") or 1))
        result.setdefault("snapshot_revision", int(row.get("revision") or 0))
        result.setdefault("base_revision", int(row.get("revision") or 0))
        result.setdefault("generated_at", row.get("updated_at") or utc_now())
        return result

    def push_snapshot(self, payload: dict[str, Any], auth: RequestAuth, *, client_ip: str, if_match: str = "") -> dict[str, Any]:
        user_id = str(payload.get("user_id") or "").strip()
        if not user_id:
            raise HTTPException(status_code=422, detail="user_id is required")

        self.ensure_user(user_id, username=str((payload.get("user") or {}).get("username") or ""), client_ip=client_ip)

        current = self._get_snapshot_row(user_id)
        current_revision = int(current["revision"]) if current else 0
        current_etag = str(current["etag"] or "") if current else ""

        if if_match and current_etag and if_match != current_etag:
            conflict = {
                "error": "etag_mismatch",
                "current_revision": current_revision,
                "updated_at": str(current["updated_at"]),
                "snapshot": self._current_snapshot_doc(current),
                "server_version": settings.server_version,
            }
            raise HTTPException(status_code=409, detail={"conflict_info": conflict})

        base_revision = int(payload.get("base_revision") or payload.get("snapshot_revision") or current_revision or 0)
        new_revision = current_revision + 1 if current_revision else max(1, base_revision + 1)

        snapshot_doc = dict(payload)
        snapshot_doc["user_id"] = user_id
        snapshot_doc["snapshot_revision"] = new_revision
        snapshot_doc["base_revision"] = base_revision
        snapshot_doc.setdefault("generated_at", utc_now())
        snapshot_doc.setdefault("schema_version", int(snapshot_doc.get("schema_version") or 1))

        payload_text = canonical_json(snapshot_doc)
        payload_hash = sha256_hex(payload_text)
        payload_size = len(payload_text.encode("utf-8"))
        compressed_size = len(zlib.compress(payload_text.encode("utf-8"), level=9))
        etag = sha256_hex(f"{user_id}:{new_revision}:{payload_hash}")[:32]

        with self._conn() as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO snapshots(user_id, revision, schema_version, payload_json, payload_hash, payload_size, compressed_size, etag, updated_at, created_at)
                    VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, NOW(), NOW())
                    ON CONFLICT (user_id) DO UPDATE SET
                        revision = EXCLUDED.revision,
                        schema_version = EXCLUDED.schema_version,
                        payload_json = EXCLUDED.payload_json,
                        payload_hash = EXCLUDED.payload_hash,
                        payload_size = EXCLUDED.payload_size,
                        compressed_size = EXCLUDED.compressed_size,
                        etag = EXCLUDED.etag,
                        updated_at = NOW()
                    """,
                    (
                        user_id,
                        new_revision,
                        int(snapshot_doc.get("schema_version") or 1),
                        payload_text,
                        payload_hash,
                        payload_size,
                        compressed_size,
                        etag,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO snapshot_history(user_id, revision, schema_version, payload_json, payload_hash, payload_size, compressed_size, etag)
                    VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        new_revision,
                        int(snapshot_doc.get("schema_version") or 1),
                        payload_text,
                        payload_hash,
                        payload_size,
                        compressed_size,
                        etag,
                    ),
                )
                conn.execute(
                    "UPDATE users SET last_seen_at = NOW(), last_client_ip = %s, updated_at = NOW() WHERE id = %s",
                    (client_ip, user_id),
                )
                conn.execute(
                    "UPDATE signals SET status = 'processed' WHERE user_id = %s AND status = 'pending'",
                    (user_id,),
                )
                conn.execute(
                    "DELETE FROM snapshot_history WHERE user_id = %s AND id NOT IN (SELECT id FROM snapshot_history WHERE user_id = %s ORDER BY revision DESC, id DESC LIMIT %s)",
                    (user_id, user_id, settings.snapshot_history_limit),
                )

        self._log_audit("push", user_id, client_ip, 200, {"revision": new_revision, "base_revision": base_revision}, sha256_hex(auth.secret)[:16])

        return {
            "ok": True,
            "user_id": user_id,
            "revision": new_revision,
            "snapshot_revision": new_revision,
            "updated_at": utc_now(),
            "payload_hash": payload_hash,
            "payload_size": payload_size,
            "compressed_size": compressed_size,
            "server_version": settings.server_version,
            "payload_encoding": "jsonb",
            "snapshot": snapshot_doc,
            "metadata": {
                "revision": new_revision,
                "updated_at": utc_now(),
                "payload_hash": payload_hash,
                "payload_size": payload_size,
                "compressed_size": compressed_size,
                "schema_version": int(snapshot_doc.get("schema_version") or 1),
                "etag": etag,
            },
            "etag": etag,
            "conflict_info": None,
        }

    def pull_snapshot(self, user_id: str, auth: RequestAuth, *, client_ip: str, since_revision: int = 0, mode: str = "full") -> dict[str, Any]:
        user_id = (user_id or "").strip()
        if not user_id:
            raise HTTPException(status_code=422, detail="user_id is required")
        row = self._get_snapshot_row(user_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        snapshot = self._current_snapshot_doc(row)
        current_revision = int(row["revision"] or 0)
        metadata = {
            "revision": current_revision,
            "updated_at": str(row["updated_at"]),
            "payload_hash": str(row["payload_hash"] or ""),
            "payload_size": int(row["payload_size"] or 0),
            "compressed_size": int(row["compressed_size"] or 0),
            "schema_version": int(row["schema_version"] or 1),
            "etag": str(row["etag"] or ""),
        }

        self._log_audit("pull", user_id, client_ip, 200, {"revision": current_revision, "mode": mode, "since_revision": since_revision}, sha256_hex(auth.secret)[:16])

        if mode == "metadata":
            return {
                "ok": True,
                "user_id": user_id,
                "revision": current_revision,
                "snapshot_revision": current_revision,
                "updated_at": metadata["updated_at"],
                "payload_hash": metadata["payload_hash"],
                "payload_size": metadata["payload_size"],
                "compressed_size": metadata["compressed_size"],
                "schema_version": metadata["schema_version"],
                "server_version": settings.server_version,
                "etag": metadata["etag"],
                "metadata": metadata,
                "snapshot": None,
                "delta": None,
                "conflict_info": None,
            }

        delta = None
        if settings.enable_delta_sync and mode == "delta" and since_revision and since_revision < current_revision:
            delta = {
                "from_revision": since_revision,
                "to_revision": current_revision,
                "snapshot": snapshot,
            }

        return {
            "ok": True,
            "user_id": user_id,
            "revision": current_revision,
            "snapshot_revision": current_revision,
            "updated_at": metadata["updated_at"],
            "payload_hash": metadata["payload_hash"],
            "payload_size": metadata["payload_size"],
            "compressed_size": metadata["compressed_size"],
            "server_version": settings.server_version,
            "payload_encoding": "jsonb",
            "snapshot": None if delta else snapshot,
            "metadata": metadata,
            "delta": delta,
            "etag": metadata["etag"],
            "conflict_info": None,
        }

    def get_meta(self, user_id: str, auth: RequestAuth, *, client_ip: str) -> dict[str, Any]:
        row = self._get_snapshot_row(user_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        meta = {
            "ok": True,
            "user_id": user_id,
            "revision": int(row["revision"] or 0),
            "updated_at": str(row["updated_at"]),
            "payload_hash": str(row["payload_hash"] or ""),
            "payload_size": int(row["payload_size"] or 0),
            "compressed_size": int(row["compressed_size"] or 0),
            "schema_version": int(row["schema_version"] or 1),
            "server_version": settings.server_version,
            "etag": str(row["etag"] or ""),
        }
        self._log_audit("meta", user_id, client_ip, 200, {"revision": meta["revision"]}, sha256_hex(auth.secret)[:16])
        return meta

    def get_status(self, user_id: str, auth: RequestAuth, *, client_ip: str) -> dict[str, Any]:
        row = self._get_snapshot_row(user_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        status = {
            "ok": True,
            "user_id": user_id,
            "revision": int(row["revision"] or 0),
            "updated_at": str(row["updated_at"]),
            "signals_pending": self._signal_count(user_id),
            "history_available": self._history_count(user_id),
            "server_version": settings.server_version,
        }
        self._log_audit("status", user_id, client_ip, 200, {"revision": status["revision"]}, sha256_hex(auth.secret)[:16])
        return status

    def list_changes(self, user_id: str, since_revision: int, auth: RequestAuth, *, client_ip: str) -> dict[str, Any]:
        row = self._get_snapshot_row(user_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT revision, schema_version, payload_hash, payload_size, compressed_size, created_at
                FROM snapshot_history
                WHERE user_id = %s AND revision > %s
                ORDER BY revision ASC
                LIMIT 200
                """,
                (user_id, int(since_revision)),
            ).fetchall()
        changes = [
            {
                "revision": int(r["revision"] or 0),
                "schema_version": int(r["schema_version"] or 1),
                "payload_hash": str(r["payload_hash"] or ""),
                "payload_size": int(r["payload_size"] or 0),
                "compressed_size": int(r["compressed_size"] or 0),
                "created_at": str(r["created_at"] or ""),
            }
            for r in rows
        ]
        self._log_audit("changes", user_id, client_ip, 200, {"since_revision": since_revision, "count": len(changes)}, sha256_hex(auth.secret)[:16])
        return {
            "ok": True,
            "user_id": user_id,
            "since_revision": since_revision,
            "revision": int(row["revision"] or 0),
            "changes": changes,
            "server_version": settings.server_version,
        }

    def record_signal(self, signal: dict[str, Any], auth: RequestAuth, *, client_ip: str) -> dict[str, Any]:
        user_id = str(signal.get("user_id") or "").strip()
        if not user_id:
            raise HTTPException(status_code=422, detail="user_id is required")
        signal_type = str(signal.get("signal_type") or "ping").strip() or "ping"
        message = str(signal.get("message") or "").strip()
        base_revision = int(signal.get("base_revision") or 0)
        payload_json = signal if isinstance(signal, dict) else {}
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=settings.signal_ttl_days * 86400))
        self.ensure_user(user_id, client_ip=client_ip)
        with self._conn() as conn:
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO signals(user_id, signal_type, message, base_revision, payload_json, status, expires_at, reserved_json)
                    VALUES (%s, %s, %s, %s, %s::jsonb, 'pending', %s, '{}'::jsonb)
                    """,
                    (user_id, signal_type, message, base_revision, canonical_json(payload_json), expires_at),
                )
                conn.execute(
                    "UPDATE users SET last_signal_at = NOW(), last_seen_at = NOW(), last_client_ip = %s, updated_at = NOW() WHERE id = %s",
                    (client_ip, user_id),
                )
        self._log_audit("signal", user_id, client_ip, 200, {"signal_type": signal_type, "base_revision": base_revision}, sha256_hex(auth.secret)[:16])
        return {
            "ok": True,
            "user_id": user_id,
            "signal_type": signal_type,
            "received_at": utc_now(),
            "revision": int(self._get_snapshot_row(user_id)["revision"]) if self._get_snapshot_row(user_id) else 0,
            "server_version": settings.server_version,
        }

    def stats(self) -> dict[str, Any]:
        with self._conn() as conn:
            users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            snapshots = conn.execute("SELECT COUNT(*) AS c FROM snapshots").fetchone()["c"]
            signals = conn.execute("SELECT COUNT(*) AS c FROM signals").fetchone()["c"]
            history = conn.execute("SELECT COUNT(*) AS c FROM snapshot_history").fetchone()["c"]
            audit_rows = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
        return {
            "users": int(users),
            "snapshots": int(snapshots),
            "signals": int(signals),
            "snapshot_history": int(history),
            "audit_rows": int(audit_rows),
            "database_path": self.dsn,
            "server_version": settings.server_version,
            "protocol_version": settings.protocol_version,
            "max_payload_bytes": int(settings.max_payload_bytes),
            "request_timeout_s": float(settings.request_timeout_s),
        }

    def init_db(self) -> dict[str, Any]:
        return self.init_schema()

    def vacuum(self) -> dict[str, Any]:
        with self._conn() as conn:
            conn.autocommit = True
            conn.execute("VACUUM (ANALYZE)")
        return {"ok": True, "database": self.dsn, "server_version": settings.server_version}

    def cleanup(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM signals WHERE expires_at < NOW()")
            conn.execute("DELETE FROM snapshot_history h USING snapshots s WHERE h.user_id = s.user_id AND h.revision <= GREATEST(0, s.revision - %s)", (settings.snapshot_history_limit,))
