"""
Rate limiting middleware for API endpoints
"""
from fastapi import HTTPException, status, Request
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter for local use"""

    def __init__(self):
        # Dict[str, List[datetime]] - tracks requests per key (client_ip:path)
        self.requests = defaultdict(list)

        # Define rate limits: path -> (max_requests, window_seconds)
        self.limits = {
            "/api/analysis/start": (5, 60),  # 5 requests per 60 seconds
            "/api/findings/fetch": (10, 60),  # 10 requests per 60 seconds
        }

        # Cleanup tracking to prevent memory leak
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # Cleanup every 5 minutes

    async def check_rate_limit(self, request: Request):
        """
        Check if request exceeds rate limit.

        Args:
            request: FastAPI Request object

        Raises:
            HTTPException: If rate limit exceeded
        """
        # Periodic cleanup to prevent memory leak
        self._cleanup_old_requests()

        # Handle case where client info is unavailable (e.g., behind proxy, in tests)
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # No limit for paths not in configuration
        if path not in self.limits:
            return

        max_requests, window_seconds = self.limits[path]

        now = datetime.now()
        key = f"{client_ip}:{path}"

        # Clean old requests outside the time window
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if now - req_time < timedelta(seconds=window_seconds)
        ]

        # Check limit
        if len(self.requests[key]) >= max_requests:
            logger.warning(f"Rate limit exceeded for {key}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s"
            )

        # Add current request
        self.requests[key].append(now)

    def _cleanup_old_requests(self):
        """
        Remove empty request records to prevent memory leak.

        This method periodically removes keys from self.requests that have
        no timestamps left after filtering expired entries.
        """
        current_time = time.time()

        # Only cleanup periodically
        if current_time - self.last_cleanup < self.cleanup_interval:
            return

        now = datetime.now()
        keys_to_remove = []

        # Get maximum window from all limits
        max_window = max(window for _, window in self.limits.values())

        for key, timestamps in self.requests.items():
            # Filter out timestamps older than maximum window
            valid_timestamps = [
                ts for ts in timestamps
                if now - ts < timedelta(seconds=max_window)
            ]

            if not valid_timestamps:
                keys_to_remove.append(key)
            else:
                self.requests[key] = valid_timestamps

        # Remove empty keys
        for key in keys_to_remove:
            del self.requests[key]

        self.last_cleanup = current_time
        if keys_to_remove:
            logger.debug(f"Rate limiter cleanup: removed {len(keys_to_remove)} dead keys")
