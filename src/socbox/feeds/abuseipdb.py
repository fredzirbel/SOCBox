"""AbuseIPDB threat feed integration."""

from __future__ import annotations

import requests

from socbox.feeds.base import BaseFeed
from socbox.models import FeedResult


class AbuseIPDBFeed(BaseFeed):
    """Check resolved IPs against AbuseIPDB.

    Requires a free API key (1000 checks/day on free tier).
    """

    name = "AbuseIPDB"

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        """Initialize with API key.

        Args:
            api_key: AbuseIPDB API key.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self.api_url = "https://api.abuseipdb.com/api/v2/check"

    def check(self, url: str, domain: str, ip: str | None) -> FeedResult:
        """Check the resolved IP against AbuseIPDB.

        Args:
            url: The full URL (not used directly).
            domain: The registered domain.
            ip: The resolved IP address to check.

        Returns:
            FeedResult with abuse confidence score.
        """
        if not ip:
            return FeedResult(
                feed_name=self.name,
                matched=False,
                details="No IP address to check (DNS resolution may have failed)",
            )

        try:
            response = requests.get(
                self.api_url,
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                },
                timeout=self.timeout,
            )

            if response.status_code != 200:
                return FeedResult(
                    feed_name=self.name,
                    matched=False,
                    details=f"API returned status {response.status_code}",
                )

            data = response.json().get("data", {})
            confidence = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "??")
            isp = data.get("isp", "unknown")

            if confidence >= 50:
                return FeedResult(
                    feed_name=self.name,
                    matched=True,
                    details=(
                        f"Abuse confidence: {confidence}%, "
                        f"{total_reports} reports, "
                        f"ISP: {isp}, Country: {country}"
                    ),
                    raw_response=data,
                )

            if confidence > 0:
                return FeedResult(
                    feed_name=self.name,
                    matched=False,
                    details=(
                        f"Low abuse confidence: {confidence}%, "
                        f"{total_reports} reports"
                    ),
                )

            return FeedResult(
                feed_name=self.name,
                matched=False,
                details=f"No abuse reports for {ip}",
            )

        except requests.exceptions.RequestException as e:
            return FeedResult(
                feed_name=self.name,
                matched=False,
                details=f"Request failed: {e}",
            )
