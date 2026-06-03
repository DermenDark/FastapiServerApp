from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_ALLOWED_SIGNAL_TYPES = {
    "ping",
    "heartbeat",
    "sync_started",
    "sync_finished",
    "sync_failed",
    "snapshot_pushed",
    "snapshot_pulled",
    "custom",
}


class SyncPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_id: str = Field(min_length=1, max_length=128)
    base_revision: int = Field(default=0, ge=0)
    user: dict[str, Any] = Field(default_factory=dict)
    settings: dict[str, Any] = Field(default_factory=dict)
    inbox_queue: list[dict[str, Any]] = Field(default_factory=list)
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    action_log: list[dict[str, Any]] = Field(default_factory=list)
    capture_session: dict[str, Any] = Field(default_factory=dict)
    schema_version: int = Field(default=1, ge=1, le=100)
    tables: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    generated_at: str = ""
    sync_meta: dict[str, Any] = Field(default_factory=dict)
    user_api_key: str = Field(default="", max_length=256)

    @field_validator("user_id")
    @classmethod
    def _strip_user_id(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("user_id is required")
        return value

    @field_validator("user", "settings", "capture_session", "sync_meta")
    @classmethod
    def _validate_object_dict(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("expected object")
        return value

    @field_validator("tables")
    @classmethod
    def _validate_tables(cls, value: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("tables must be an object")
        normalized: dict[str, list[dict[str, Any]]] = {}
        for table_name, rows in value.items():
            if not isinstance(table_name, str) or not table_name.strip():
                raise ValueError("table names must be non-empty strings")
            if rows is None:
                normalized[table_name.strip()] = []
                continue
            if not isinstance(rows, list):
                raise ValueError(f"table '{table_name}' must contain a list of rows")
            normalized_rows: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError(f"table '{table_name}' rows must be objects")
                normalized_rows.append(row)
            normalized[table_name.strip()] = normalized_rows
        return normalized

    @field_validator("user_api_key")
    @classmethod
    def _strip_api_key(cls, value: str) -> str:
        return (value or "").strip()

    @model_validator(mode="after")
    def _cross_validate(self) -> "SyncPayload":
        user = self.user or {}
        nested_id = str(user.get("id") or "").strip()
        if nested_id and nested_id != self.user_id:
            raise ValueError("user.id must match user_id")
        if nested_id:
            user["id"] = nested_id
            self.user = user
        return self


class SyncPullRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=128)
    since_revision: int = Field(default=0, ge=0)
    mode: Literal["full", "metadata", "delta"] = "full"

    @field_validator("user_id")
    @classmethod
    def _strip_user_id(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("user_id is required")
        return value


class SyncMetaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=128)

    @field_validator("user_id")
    @classmethod
    def _strip_user_id(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("user_id is required")
        return value


class UserRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=128)

    @field_validator("user_id")
    @classmethod
    def _strip_user_id(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("user_id is required")
        return value


class SignalPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_id: str = Field(min_length=1, max_length=128)
    signal_type: str = Field(default="ping", min_length=1, max_length=64)
    message: str = Field(default="", max_length=1000)
    base_revision: int = Field(default=0, ge=0)
    payload: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(default="client", max_length=64)

    @field_validator("user_id")
    @classmethod
    def _strip_user_id(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("user_id is required")
        return value

    @field_validator("signal_type")
    @classmethod
    def _validate_signal_type(cls, value: str) -> str:
        normalized = (value or "").strip()
        if normalized not in _ALLOWED_SIGNAL_TYPES:
            return "custom"
        return normalized

    @field_validator("message", "source")
    @classmethod
    def _strip_text(cls, value: str) -> str:
        return (value or "").strip()

    @field_validator("payload")
    @classmethod
    def _validate_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("payload must be an object")
        return value


class SyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    user_id: str
    revision: int
    snapshot_revision: int
    updated_at: str
    payload_hash: str
    payload_size: int
    compressed_size: int
    server_version: str
    payload_encoding: str = "jsonb"
    snapshot: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None
    delta: dict[str, Any] | None = None
    etag: str | None = None
    conflict_info: dict[str, Any] | None = None


class SignalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    user_id: str
    signal_type: str
    received_at: str
    revision: int
    server_version: str


class StatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    user_id: str
    revision: int
    updated_at: str
    signals_pending: int
    history_available: int
    server_version: str


class MetaResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    user_id: str
    revision: int
    updated_at: str
    payload_hash: str
    payload_size: int
    compressed_size: int
    schema_version: int
    server_version: str
    etag: str | None = None


class ConflictInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: str
    current_revision: int
    updated_at: str
    snapshot: dict[str, Any] | None = None
    server_version: str


class StatsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    users: int
    snapshots: int
    signals: int
    snapshot_history: int
    audit_rows: int
    database_path: str
    server_version: str
    protocol_version: str
    max_payload_bytes: int
    request_timeout_s: float


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    service: str
    time: str
    server_version: str
    protocol_version: str


class ReadyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    ready: bool = True
    database: str
    server_version: str
    protocol_version: str
