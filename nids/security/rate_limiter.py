"""
In-Memory Sliding-Window Rate Limiter for Home-Gateway NIDS.
Protects against denial-of-service, brute-force, and resource exhaustion with strict client bounds.
"""

from collections import deque
from functools import wraps
import time
import threading
from typing import Dict, Deque, Callable
from flask import request, jsonify


class RateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter with bounded memory footprint.
    """

    def __init__(self, default_limit: int = 120, window_seconds: float = 60.0, max_clients: int = 10000):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._clients: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def _prune_inactive_clients(self, now: float) -> None:
        """Evicts expired clients or forces oldest eviction when capacity is reached."""
        cutoff = now - self.window_seconds
        expired = [cid for cid, history in self._clients.items() if not history or history[-1] < cutoff]
        for cid in expired:
            del self._clients[cid]

        # If still over bound, evict oldest 10%
        if len(self._clients) >= self.max_clients:
            sorted_clients = sorted(
                self._clients.keys(),
                key=lambda cid: self._clients[cid][-1] if self._clients[cid] else 0
            )
            for cid in sorted_clients[:max(1, int(self.max_clients * 0.10))]:
                self._clients.pop(cid, None)

    def is_allowed(self, client_id: str, limit: int) -> bool:
        now = time.time()
        with self._lock:
            if client_id not in self._clients:
                if len(self._clients) >= self.max_clients:
                    self._prune_inactive_clients(now)
                self._clients[client_id] = deque()

            history = self._clients[client_id]
            cutoff = now - self.window_seconds

            # Evict timestamps outside sliding window
            while history and history[0] < cutoff:
                history.popleft()

            if len(history) >= limit:
                return False

            history.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._clients.clear()


# Global rate limiter instance
_global_rate_limiter = RateLimiter(default_limit=120, window_seconds=60.0, max_clients=10000)


def rate_limit(requests_per_minute: int = 60) -> Callable:
    """
    Decorator to apply rate limiting to Flask routes.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr or "127.0.0.1"
            key = f"{client_ip}:{request.endpoint}"
            if not _global_rate_limiter.is_allowed(key, requests_per_minute):
                return jsonify({
                    "error": "Too Many Requests: Rate limit exceeded. Please try again later.",
                    "status_code": 429
                }), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator
