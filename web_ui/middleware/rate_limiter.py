"""
Rate limiting middleware for API endpoints
"""
from fastapi import HTTPException, status, Request
from collections import defaultdict
from datetime import datetime, timedelta
import logging

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

    async def check_rate_limit(self, request: Request):
        """
        Check if request exceeds rate limit.

        Args:
            request: FastAPI Request object

        Raises:
            HTTPException: If rate limit exceeded
        """
        client_ip = request.client.host
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
