"""Per-agent rate limiting (token bucket, in-memory)."""

from __future__ import annotations

import threading
import time


class TokenBucketRateLimiter:
    """Classic token bucket keyed by agent id.

    capacity: burst size; refill_per_second: sustained rate.
    Not multi-process safe — front with a shared limiter (e.g., Redis) at scale;
    the interface here is the contract such backends implement.
    """

    def __init__(self, capacity: float, refill_per_second: float):
        if capacity <= 0 or refill_per_second <= 0:
            raise ValueError("capacity and refill_per_second must be positive")
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_second)
        self._buckets: dict[str, tuple[float, float]] = {}  # id -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last_ts = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last_ts) * self.refill_per_second)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return True
            self._buckets[key] = (tokens, now)
            return False
