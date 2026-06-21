"""VirusTotal threat feed integration."""

from __future__ import annotations

import base64

import requests

from iris.feeds.base import BaseFeed
from iris.models import FeedResult


def vt_url_id(url: str) -> str:
    """Return the unpadded base64url-encoded URL ID used by VirusTotal's API."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


# Categories VirusTotal counts in its displayed detection ratio — engines that
# actually returned a verdict. Summing *all* of last_analysis_stats instead would
# also count type-unsupported / failure / timeout / confirmed-timeout, inflating
# the denominator above the "X / Y" VT itself shows.
_VT_VERDICT_CATEGORIES = ("malicious", "suspicious", "undetected", "harmless")


def scanned_engine_total(stats: dict) -> int:
    """Number of engines that returned a verdict (matches VT's displayed total)."""
    return sum(int(stats.get(cat, 0) or 0) for cat in _VT_VERDICT_CATEGORIES)


class VirusTotalFeed(BaseFeed):
    """Check URLs against VirusTotal's API v3.

    Requires a free API key (4 requests/minute on free tier).
    """

    name = "VirusTotal"

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        """Initialize with API key.

        Args:
            api_key: VirusTotal API key.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "https://www.virustotal.com/api/v3"

    def check(self, url: str, domain: str, ip: str | None) -> FeedResult:
        """Check the URL against VirusTotal.

        Args:
            url: The full URL to check.
            domain: The registered domain.
            ip: The resolved IP address.

        Returns:
            FeedResult with match status and detection details.
        """
        try:
            url_id = vt_url_id(url)

            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers={"x-apikey": self.api_key},
                timeout=self.timeout,
            )

            if response.status_code == 404:
                return FeedResult(
                    feed_name=self.name,
                    matched=False,
                    details="URL not found in VirusTotal database",
                )

            if response.status_code != 200:
                return FeedResult(
                    feed_name=self.name,
                    matched=False,
                    details=f"API returned status {response.status_code}",
                )

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = scanned_engine_total(stats)

            detection_count = malicious + suspicious
            detection_rate = detection_count / total if total > 0 else 0.0

            details = (
                f"{malicious} malicious, {suspicious} suspicious "
                f"detections out of {total} engines"
            )

            # Require at least 3 detections or >5% detection rate to
            # avoid false positives from a single noisy engine
            if detection_count >= 3 or detection_rate > 0.05:
                return FeedResult(
                    feed_name=self.name,
                    matched=True,
                    details=details,
                    raw_response=stats,
                )

            if detection_count > 0:
                return FeedResult(
                    feed_name=self.name,
                    matched=False,
                    details=f"Low confidence: {details}",
                )

            return FeedResult(
                feed_name=self.name,
                matched=False,
                details=f"Clean: 0 detections out of {total} engines",
            )

        except requests.exceptions.RequestException as e:
            return FeedResult(
                feed_name=self.name,
                matched=False,
                details=f"Request failed: {e}",
            )
