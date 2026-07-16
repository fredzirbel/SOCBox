"""Base threat feed interface for SOC Box."""

from __future__ import annotations

from abc import ABC, abstractmethod

from socbox.models import FeedResult


class BaseFeed(ABC):
    """Abstract base class for threat feed integrations.

    Each feed checks a URL, domain, or IP against an external
    threat intelligence source.
    """

    name: str = ""

    @abstractmethod
    def check(self, url: str, domain: str, ip: str | None) -> FeedResult:
        """Check the URL/domain/IP against this threat feed.

        Args:
            url: The full URL to check.
            domain: The registered domain.
            ip: The resolved IP address, or None if resolution failed.

        Returns:
            A FeedResult indicating whether a match was found.
        """
        ...
