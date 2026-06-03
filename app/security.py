from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request

from .config import settings


@dataclass(slots=True)
class RequestAuth:
    user_id: str = ""
    secret: str = ""
    secret_kind: str = "sync_key"
    signed: bool = False


class NonceCache:
    def __init__(self, ttl_seconds: int) -> None:
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._lock = threading.RLock()
        self._seen: dict[str, float] = {}

    def add(self, key: str, nonce: str) -> None:
        marker = f"{key}:{nonce}".strip(":")
        now = time.time()
        cutoff = now - self.ttl_seconds
        with self._lock:
            expired = [n for n, ts in self._seen.items() if ts < cutoff]
            for n in expired:
                self._seen.pop(n, None)
            if marker in self._seen:
                raise HTTPException(status_code=409, detail="replay_detected")
            self._seen[marker] = now


class TokenBucketLimiter:
    def __init__(self, capacity: float, refill_per_second: float) -> None:
        self.capacity = max(1.0, float(capacity))
        self.refill_per_second = max(0.01, float(refill_per_second))
        self._lock = threading.RLock()
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, cost: float = 1.0) -> bool:
        key = key or "anonymous"
        now = time.time()
        with self._lock:
            tokens, updated = self._buckets.get(key, (self.capacity, now))
            elapsed = max(0.0, now - updated)
            tokens = min(self.capacity, tokens + elapsed * self.refill_per_second)
            if tokens < cost:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - cost, now)
            return True


nonce_cache = NonceCache(settings.request_nonce_ttl_s)
rate_limiter = TokenBucketLimiter(settings.rate_limit_burst, settings.rate_limit_per_second)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_hex_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_string(method: str, path: str, user_id: str, timestamp: str, nonce: str, body_hash: str) -> str:
    return "\n".join([
        method.upper().strip(),
        path.strip(),
        (user_id or "").strip(),
        (timestamp or "").strip(),
        (nonce or "").strip(),
        (body_hash or "").strip(),
    ])


def sign_request(secret: str, canonical: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(secret: str, canonical: str, signature: str) -> bool:
    expected = sign_request(secret, canonical)
    return hmac.compare_digest(expected, (signature or "").strip())


def extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    client = request.client
    return client.host if client and client.host else "unknown"


def enforce_rate_limit(key: str) -> None:
    if not rate_limiter.allow(key):
        raise HTTPException(status_code=429, detail="rate_limited")
