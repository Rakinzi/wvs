from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass

import redis
from fastapi import Request


@dataclass(frozen=True)
class Limit:
    requests: int
    window_seconds: int


AUTH_LIMITS: dict[tuple[str, str], Limit] = {
    ("POST", "/login"): Limit(10, 60),
    ("POST", "/register"): Limit(5, 3600),
    ("POST", "/forgot-password"): Limit(5, 3600),
    ("POST", "/reset-password"): Limit(10, 3600),
    ("POST", "/verify-email/resend"): Limit(5, 3600),
}


class RateLimiter:
    """Fixed-window limiter backed by Redis in production and memory in development."""

    def __init__(self, storage_uri: str) -> None:
        self._redis = redis.Redis.from_url(storage_uri) if storage_uri.startswith("redis") else None
        self._memory: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def limit_for(request: Request) -> Limit | None:
        configured = AUTH_LIMITS.get((request.method, request.url.path))
        if configured:
            return configured
        if request.method == "POST" and request.url.path == "/scan":
            return Limit(30, 3600)
        return None

    @staticmethod
    def _key(request: Request, limit: Limit, now: int) -> str:
        client = request.client.host if request.client else "unknown"
        auth_cookie = request.cookies.get("access_token_cookie", "")
        identity = hashlib.sha256(auth_cookie.encode()).hexdigest()[:16] if auth_cookie else client
        window = now // limit.window_seconds
        path = request.url.path.replace("/", ":")
        return f"launchguard:rate:{request.method}:{path}:{identity}:{window}"

    def check(self, request: Request, limit: Limit) -> tuple[bool, int, int]:
        now = int(time.time())
        retry_after = limit.window_seconds - (now % limit.window_seconds)
        key = self._key(request, limit, now)

        if self._redis is not None:
            try:
                with self._redis.pipeline() as pipe:
                    pipe.incr(key)
                    pipe.expire(key, retry_after + 1)
                    count, _ = pipe.execute()
                return count <= limit.requests, max(0, limit.requests - count), retry_after
            except redis.RedisError:
                # Keep the API available if Redis is briefly unavailable.
                pass

        expires_at = now + retry_after
        with self._lock:
            count, stored_expiry = self._memory.get(key, (0, expires_at))
            if stored_expiry <= now:
                count, stored_expiry = 0, expires_at
            count += 1
            self._memory[key] = (count, stored_expiry)
        return count <= limit.requests, max(0, limit.requests - count), retry_after
