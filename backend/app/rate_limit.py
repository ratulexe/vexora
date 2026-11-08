"""Sliding-window rate limits, kept in memory.

Every analysis can call paid or rate-limited services (the Claude API, threat
feeds), and every registry submission spends testnet gas, so each visitor gets a
budget. There is also one shared hourly budget for AI calls, so traffic spread
across many addresses still cannot drain the API credit.
"""

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

_ALL: list["RateLimiter"] = []


class RateLimiter:
    def __init__(self, name: str, limit: int, window_seconds: float):
        self.name = name
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()
        _ALL.append(self)

    def allow(self, key: str) -> bool:
        """Records one use and returns True, or returns False if the budget is spent."""
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] > self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            # Forget visitors with no recent activity, so memory stays bounded.
            if len(self._events) > 10_000:
                for stale in [k for k, v in self._events.items() if not v or now - v[-1] > self.window_seconds]:
                    del self._events[stale]
            return True

    def check(self, request: Request, message: str) -> None:
        """Raises HTTP 429 if this visitor has used up their budget."""
        if not self.allow(client_ip(request)):
            minutes = max(1, round(self.window_seconds / 60))
            raise HTTPException(429, f"{message} You can make {self.limit} every {minutes} minutes.")

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


def clear_all() -> None:
    for limiter in _ALL:
        limiter.clear()


def client_ip(request: Request) -> str:
    """The visitor's address. Render sits behind Cloudflare, which sets CF-Connecting-IP
    itself (visitors cannot forge it through Cloudflare). X-Forwarded-For is a fallback."""
    for header in ("cf-connecting-ip", "true-client-ip"):
        if value := request.headers.get(header, "").strip():
            return value
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")


LINK_ANALYSIS = RateLimiter("link analysis", limit=30, window_seconds=600)
MESSAGE_ANALYSIS = RateLimiter("message analysis", limit=20, window_seconds=600)
QR_ANALYSIS = RateLimiter("QR analysis", limit=20, window_seconds=600)
REGISTRATION = RateLimiter("registry submissions", limit=5, window_seconds=600)
AI_CALLS = RateLimiter("AI calls, all visitors", limit=200, window_seconds=3600)
