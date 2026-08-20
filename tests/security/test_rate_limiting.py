"""
Security Tests: Rate Limiting Enforcement.
Verifies excessive requests to API endpoints return HTTP 429 Too Many Requests.
"""

import pytest
from nids.security.rate_limiter import RateLimiter


def test_rate_limiter_blocks_burst():
    limiter = RateLimiter(default_limit=5, window_seconds=60.0)
    client_id = "192.168.1.10:stats"

    # First 5 requests succeed
    for _ in range(5):
        assert limiter.is_allowed(client_id, limit=5) is True

    # 6th request is blocked
    assert limiter.is_allowed(client_id, limit=5) is False
