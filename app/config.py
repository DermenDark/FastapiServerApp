from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip() or default)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)).strip() or default)
    except Exception:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    # Railway exposes DATABASE_URL for PostgreSQL; keep a local fallback for dev.
    database_url: str = os.getenv(
        "DATABASE_URL",
        os.getenv("POSTGRES_DSN", "postgresql://postgres:postgres@localhost:5432/content_sync"),
    ).strip()

    sync_key: str = os.getenv("SYNC_KEY", "").strip()
    host: str = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
    port: int = _env_int("PORT", 8000)

    max_payload_mb: int = _env_int("MAX_PAYLOAD_MB", 25)
    allow_public_health: bool = _env_bool("ALLOW_PUBLIC_HEALTH", True)
    enable_delta_sync: bool = _env_bool("ENABLE_DELTA_SYNC", True)
    snapshot_history_limit: int = max(1, _env_int("SNAPSHOT_HISTORY_LIMIT", 20))
    signal_ttl_days: int = max(1, _env_int("SIGNAL_TTL_DAYS", 30))
    signal_max_per_user: int = max(10, _env_int("SIGNAL_MAX_PER_USER", 5000))
    request_timeout_s: float = _env_float("REQUEST_TIMEOUT_S", 10.0)

    protocol_version: str = os.getenv("PROTOCOL_VERSION", "3.0.0").strip() or "3.0.0"
    server_version: str = os.getenv("SERVER_VERSION", "3.0.0").strip() or "3.0.0"

    require_signed_requests: bool = _env_bool("REQUIRE_SIGNED_REQUESTS", False)
    request_signature_ttl_s: int = max(5, _env_int("REQUEST_SIGNATURE_TTL_S", 300))
    request_nonce_ttl_s: int = max(5, _env_int("REQUEST_NONCE_TTL_S", 600))
    rate_limit_burst: int = max(1, _env_int("RATE_LIMIT_BURST", 30))
    rate_limit_per_second: float = max(0.1, _env_float("RATE_LIMIT_PER_SECOND", 5.0))

    @property
    def max_payload_bytes(self) -> int:
        return self.max_payload_mb * 1024 * 1024


settings = Settings()
