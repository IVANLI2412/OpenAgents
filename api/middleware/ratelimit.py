"""Rate limiting middleware for the OpenAgents API.

@fix-author
name: IVANLI2412 (APEX autonomous agent)
date: 2026-11-21T00:00:00-03:00
runtime: os=Windows, arch=AMD64, working_dir=C:\Users\User\pumpfun-quant-ai, shell=powershell
initialization: See AGENTS.md project rules — PAPER mode by default, signer isolated, RiskAnalyst veto absolute, no live trading without explicit written owner authorization.
"""

import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Private / loopback IP ranges blocked for client-IP derivation (SSRF / spoofing protection)
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                       "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                       "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
                       "127.", "::1", "fc00:", "fe80:")


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(PRIVATE_IP_PREFIXES)


class RateLimitConfig:
    """Per-endpoint rate limit configuration."""

    def __init__(
        self,
        requests_per_window: int = 100,
        window_seconds: int = 60,
        burst_limit: int = 20,
        trusted_proxies: Optional[List[str]] = None,
    ):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.burst_limit = burst_limit
        self.trusted_proxies = trusted_proxies or []


# Persistent SQLite store — counters survive middleware restart.
_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "ratelimit.sqlite"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    conn.execute(
        """CREATE TABLE IF NOT EXISTS rate_limit_entries (
            client_ip TEXT NOT NULL,
            endpoint  TEXT NOT NULL,
            timestamp REAL NOT NULL,
            PRIMARY KEY (client_ip, endpoint)
        )"""
    )
    conn.commit()
    return conn


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: RateLimitConfig = None):
        super().__init__(app)
        self.config = config or RateLimitConfig()

    def _get_client_ip(self, request: Request) -> str:
        """Return the real client IP.

        X-Forwarded-For is ONLY honoured when the direct peer is a configured
        trusted proxy. Otherwise the direct connection IP is used, which
        prevents header spoofing from bypassing rate limits.
        """
        direct = request.client.host if request.client else "unknown"

        # If a trusted proxy is configured and the direct peer matches it,
        # use the first non-private, non-proxy entry from X-Forwarded-For.
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded and direct in self.config.trusted_proxies:
            for entry in forwarded.split(","):
                entry = entry.strip()
                if entry and not _is_private_ip(entry) and entry not in self.config.trusted_proxies:
                    return entry

        # Fallback: direct connection IP (spoof-resistant).
        if _is_private_ip(direct) or direct == "unknown":
            return "unknown"
        return direct

    def _is_rate_limited(self, client_ip: str, endpoint: str) -> Tuple[bool, int]:
        """Sliding-window rate check backed by persistent SQLite store."""
        conn = _db()
        now = time.time()
        window_start = now - self.config.window_seconds

        # Purge expired entries for this client+endpoint.
        conn.execute(
            "DELETE FROM rate_limit_entries WHERE client_ip=? AND endpoint=? AND timestamp<?",
            (client_ip, endpoint, window_start),
        )

        # Count remaining requests in the sliding window.
        cur = conn.execute(
            "SELECT COUNT(*) FROM rate_limit_entries WHERE client_ip=? AND endpoint=?",
            (client_ip, endpoint),
        )
        count = cur.fetchone()[0]

        if count >= self.config.requests_per_window:
            # Estimate retry_after from the oldest entry in the window.
            cur = conn.execute(
                "SELECT MIN(timestamp) FROM rate_limit_entries WHERE client_ip=? AND endpoint=?",
                (client_ip, endpoint),
            )
            oldest = cur.fetchone()[0]
            retry_after = int(oldest + self.config.window_seconds - now) + 1
            conn.close()
            return True, max(retry_after, 1)

        # Record this request.
        conn.execute(
            "INSERT INTO rate_limit_entries (client_ip, endpoint, timestamp) VALUES (?, ?, ?)",
            (client_ip, endpoint, now),
        )
        conn.commit()
        conn.close()

        remaining = self.config.requests_per_window - count - 1
        return False, remaining

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/health"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        endpoint = request.url.path
        is_limited, value = self._is_rate_limited(client_ip, endpoint)

        if is_limited:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "retry_after": value,
                },
                headers={"Retry-After": str(value)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(value)
        response.headers["X-RateLimit-Limit"] = str(self.config.requests_per_window)
        return response


def create_rate_limiter(
    requests_per_minute: int = 100,
    burst: int = 20,
) -> RateLimitMiddleware:
    config = RateLimitConfig(
        requests_per_window=requests_per_minute,
        window_seconds=60,
        burst_limit=burst,
    )
    return RateLimitMiddleware(app=None, config=config)
