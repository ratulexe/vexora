"""Small in-memory caches with expiry.

Results are reused for a limited time only: threats change, so a stored result
must expire rather than become a permanent label. Everything is lost when the
server restarts, which only means the next check runs in full.
"""

import copy
import functools
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

_ALL: list["TTLCache"] = []


class TTLCache:
    def __init__(self, name: str, ttl_seconds: float, max_entries: int = 500):
        self.name = name
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._items: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        _ALL.append(self)

    def get(self, key):
        """Returns (a copy of the value, when it was stored), or None if missing or expired."""
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            stored_monotonic, stored_at, value = item
            if time.monotonic() - stored_monotonic > self.ttl_seconds:
                del self._items[key]
                return None
            self._items.move_to_end(key)
            return copy.deepcopy(value), stored_at

    def set(self, key, value) -> None:
        with self._lock:
            self._items[key] = (time.monotonic(), datetime.now(timezone.utc), copy.deepcopy(value))
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


def clear_all() -> None:
    for cache in _ALL:
        cache.clear()


def cache_completed_checks(cache: TTLCache, key):
    """Cache a check's CheckResult, but only when the check completed: failures are retried."""

    def decorator(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            cache_key = key(*args, **kwargs)
            hit = cache.get(cache_key)
            if hit is not None:
                return hit[0]
            result = function(*args, **kwargs)
            if result.completed:
                cache.set(cache_key, result)
            return result

        return wrapper

    return decorator
