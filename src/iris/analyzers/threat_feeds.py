"""Threat feed orchestrator analyzer for IRIS."""

from __future__ import annotations

import concurrent.futures
from typing import Any
from urllib.parse import urlparse

import tldextract

from iris.analyzers.base import BaseAnalyzer
from iris.config import get_api_key
from iris.dns_util import resolve_host
from iris.feeds.abuseipdb import AbuseIPDBFeed
from iris.feeds.google_safebrowsing import GoogleSafeBrowsingFeed
from iris.feeds.virustotal import VirusTotalFeed
from iris.models import AnalyzerResult, AnalyzerStatus, FeedResult, Finding

_FEED_DISPLAY_ORDER: dict[str, int] = {
    "VirusTotal": 1,
    "AbuseIPDB": 2,
    "Google Safe Browsing": 3,
}


class ThreatFeedAnalyzer(BaseAnalyzer):
    """Orchestrate all threat feed checks against a URL.

    Initializes each feed that has a valid API key (or doesn't need one),
    runs all checks concurrently, and aggregates results. Feed results are
    stored in `last_feed_results` for the scanner to extract.
    """

    name = "Threat Feed Integration"
    weight = 20.0

    def __init__(self) -> None:
        """Initialize the analyzer with an empty feed results list."""
        self.last_feed_results: list[FeedResult] = []

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Run all configured threat feeds against the URL.

        Args:
            url: The URL to check.
            config: The loaded configuration dictionary.
            browser: Unused — accepted for interface compliance.

        Returns:
            AnalyzerResult summarizing threat feed findings.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else hostname
        timeout = config.get("requests", {}).get("timeout", 10)

        # Resolve IP
        ip = self._resolve_ip(hostname)

        # Build list of feeds with valid config
        feeds = self._build_feeds(config, timeout)

        if not feeds:
            self.last_feed_results = []
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.SKIPPED,
                score=0.0,
                max_weight=self.weight,
                error_message="No threat feeds configured (add API keys to config)",
            )

        # Run all feeds concurrently
        feed_results: list[FeedResult] = []
        findings: list[Finding] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(feeds)) as executor:
            future_to_feed = {
                executor.submit(self._check_feed, feed, url, domain, ip): feed
                for feed in feeds
            }
            for future in concurrent.futures.as_completed(future_to_feed):
                result, finding = future.result()
                feed_results.append(result)
                if finding is not None:
                    findings.append(finding)

        for fr in feed_results:
            fr.display_order = _FEED_DISPLAY_ORDER.get(fr.feed_name, 99)
        self.last_feed_results = feed_results

        # Score scales with number of matched feeds AND detection severity.
        # A single VT match with 10+ detections should score much higher
        # than a single match with 3 detections.
        score = self._compute_feed_score(feed_results)

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    @staticmethod
    def _compute_feed_score(feed_results: list[FeedResult]) -> float:
        """Compute the analyzer score based on feed matches and severity.

        Scales the score by VirusTotal detection count so that a URL
        flagged by 10+ VT engines scores much higher than one with 3.

        Args:
            feed_results: List of FeedResult from all feeds.

        Returns:
            Analyzer score on a 0-100 scale.
        """
        matches = sum(1 for fr in feed_results if fr.matched)
        if matches == 0:
            return 0.0

        # Base: each matched feed contributes 40 points (was 50)
        base = min(100.0, matches * 40.0)

        # VT severity multiplier based on detection count
        vt_boost = 0.0
        for fr in feed_results:
            if fr.feed_name == "VirusTotal" and fr.matched and fr.raw_response:
                malicious = fr.raw_response.get("malicious", 0)
                suspicious = fr.raw_response.get("suspicious", 0)
                detections = malicious + suspicious

                if detections >= 20:
                    vt_boost = 60.0
                elif detections >= 10:
                    vt_boost = 45.0
                elif detections >= 5:
                    vt_boost = 25.0
                elif detections >= 3:
                    vt_boost = 10.0

        return min(100.0, base + vt_boost)

    def _check_feed(
        self, feed: Any, url: str, domain: str, ip: str | None
    ) -> tuple[FeedResult, Finding | None]:
        """Run a single feed check with error handling.

        Args:
            feed: The feed instance to check.
            url: The URL to check.
            domain: The extracted domain.
            ip: Resolved IP address, or None.

        Returns:
            Tuple of (FeedResult, Finding or None).
        """
        try:
            result = feed.check(url, domain, ip)
            if result.matched:
                finding = Finding(
                    description=f"{result.feed_name}: {result.details}",
                    score_contribution=50.0,
                    severity="critical",
                )
            else:
                finding = Finding(
                    description=f"{result.feed_name}: {result.details}",
                    score_contribution=0.0,
                    severity="info",
                )
            return result, finding
        except Exception as e:
            result = FeedResult(
                feed_name=feed.name,
                matched=False,
                details=f"Error: {e}",
            )
            return result, None

    def _resolve_ip(self, hostname: str) -> str | None:
        """Resolve hostname to IP address.

        Uses the system resolver first, then a public DoH fallback, so feeds
        that key off the IP (e.g. AbuseIPDB) still work when the local
        resolver cannot reach the target host.

        Args:
            hostname: The hostname to resolve.

        Returns:
            IP address string, or None if resolution failed.
        """
        return resolve_host(hostname) or None

    def _build_feeds(self, config: dict[str, Any], timeout: int) -> list:
        """Build the list of feeds that have valid configuration.

        Args:
            config: The loaded configuration dictionary.
            timeout: Request timeout in seconds.

        Returns:
            List of initialized feed instances.
        """
        feeds = []

        vt_key = get_api_key(config, "virustotal")
        if vt_key:
            feeds.append(VirusTotalFeed(api_key=vt_key, timeout=timeout))

        gsb_key = get_api_key(config, "google_safebrowsing")
        if gsb_key:
            feeds.append(GoogleSafeBrowsingFeed(api_key=gsb_key, timeout=timeout))

        abuseipdb_key = get_api_key(config, "abuseipdb")
        if abuseipdb_key:
            feeds.append(AbuseIPDBFeed(api_key=abuseipdb_key, timeout=timeout))

        return feeds
