"""Google Safe Browsing threat feed integration.

Uses both the v4 Lookup API (threatMatches:find) and the v4 hash-based
API (fullHashes:find) to maximise detection coverage.  The Lookup API
checks exact URL strings while the hash API checks SHA-256 prefix hashes
of multiple URL expressions, matching the approach Chrome itself uses.
"""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import urlparse

import requests

from socbox.feeds.base import BaseFeed
from socbox.models import FeedResult


class GoogleSafeBrowsingFeed(BaseFeed):
    """Check URLs against Google Safe Browsing APIs.

    Requires a Google API key with Safe Browsing API enabled.
    """

    name = "Google Safe Browsing"

    _THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        """Initialize with API key.

        Args:
            api_key: Google API key with Safe Browsing enabled.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key
        self.timeout = timeout

    # ------------------------------------------------------------------
    # URL variant helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_url_variants(url: str) -> list[dict[str, str]]:
        """Build URL string variants for the Lookup API.

        Args:
            url: The original URL to check.

        Returns:
            A deduplicated list of ``{"url": ...}`` threat entry dicts.
        """
        parsed = urlparse(url)
        variants: list[str] = [url]

        # With / without trailing slash
        if url.endswith("/"):
            variants.append(url.rstrip("/"))
        else:
            variants.append(url + "/")

        # Base domain with scheme
        base = f"{parsed.scheme}://{parsed.netloc}/"
        variants.append(base)

        # Parent path segments
        parts = parsed.path.rstrip("/").split("/")
        for i in range(2, len(parts)):
            parent = "/".join(parts[:i]) + "/"
            variants.append(f"{parsed.scheme}://{parsed.netloc}{parent}")

        seen: set[str] = set()
        entries: list[dict[str, str]] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                entries.append({"url": v})
        return entries

    @staticmethod
    def _build_hash_prefixes(url: str) -> list[str]:
        """Build SHA-256 hash prefixes for the fullHashes API.

        Google Safe Browsing stores threats as SHA-256 hashes of URL
        expressions.  The expressions are generated per Google's URL
        canonicalisation spec: ``host/path`` (no scheme) for every
        combination of host suffixes and path prefixes.

        Args:
            url: The original URL to check.

        Returns:
            Base64-encoded 4-byte hash prefixes (deduplicated).
        """
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").rstrip(".")
        path = parsed.path or "/"

        # Build host suffixes: full host, then progressively strip
        # leading components down to eTLD+1 (minimum 2 parts).
        host_parts = hostname.split(".")
        host_variants: list[str] = [hostname]
        for i in range(1, len(host_parts) - 1):
            host_variants.append(".".join(host_parts[i:]))

        # Build path prefixes: /, /a/, /a/b/, ... and the exact path.
        path_variants: list[str] = ["/"]
        segments = path.strip("/").split("/")
        accumulated = ""
        for seg in segments:
            if not seg:
                continue
            accumulated += f"/{seg}"
            path_variants.append(accumulated + "/")
        # Exact path (without trailing slash) if different
        if path not in path_variants and path != "/":
            path_variants.append(path)

        # Combine all host × path expressions and hash them.
        seen: set[str] = set()
        prefixes: list[str] = []
        for h in host_variants:
            for p in path_variants:
                expr = f"{h}{p}"
                sha = hashlib.sha256(expr.encode()).digest()
                b64 = base64.b64encode(sha[:4]).decode()
                if b64 not in seen:
                    seen.add(b64)
                    prefixes.append(b64)
        return prefixes

    # ------------------------------------------------------------------
    # API calls
    # ------------------------------------------------------------------

    def _lookup_api(self, url: str) -> FeedResult | None:
        """Query the v4 Lookup API (threatMatches:find).

        Args:
            url: The URL to check.

        Returns:
            A FeedResult if the API returned a definitive answer, or
            None if this method should be treated as inconclusive.
        """
        payload = {
            "client": {"clientId": "socbox", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": self._THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": self._build_url_variants(url),
            },
        }
        resp = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": self.api_key},
            json=payload,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            return None

        matches = resp.json().get("matches", [])
        if matches:
            threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return FeedResult(
                feed_name=self.name,
                matched=True,
                details=f"Threat types: {', '.join(threat_types)}",
                raw_response=resp.json(),
            )
        return None  # inconclusive — try hash API next

    def _hash_api(self, url: str) -> FeedResult | None:
        """Query the v4 hash-based API (fullHashes:find).

        Args:
            url: The URL to check.

        Returns:
            A FeedResult if the API returned a definitive answer, or
            None if no match was found.
        """
        prefixes = self._build_hash_prefixes(url)
        if not prefixes:
            return None

        payload = {
            "client": {"clientId": "socbox", "clientVersion": "0.1.0"},
            "clientStates": [],
            "threatInfo": {
                "threatTypes": self._THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"hash": p} for p in prefixes],
            },
        }
        resp = requests.post(
            "https://safebrowsing.googleapis.com/v4/fullHashes:find",
            params={"key": self.api_key},
            json=payload,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            return None

        matches = resp.json().get("matches", [])
        if matches:
            threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return FeedResult(
                feed_name=self.name,
                matched=True,
                details=f"Threat types (hash match): {', '.join(threat_types)}",
                raw_response=resp.json(),
            )
        return None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check(self, url: str, domain: str, ip: str | None) -> FeedResult:
        """Check the URL against Google Safe Browsing.

        Tries the Lookup API first, then falls back to the hash-based
        API for broader coverage.

        Args:
            url: The full URL to check.
            domain: The registered domain.
            ip: The resolved IP address.

        Returns:
            FeedResult with match status.
        """
        try:
            # 1) Lookup API (exact URL match)
            result = self._lookup_api(url)
            if result is not None:
                return result

            # 2) Hash-based API (broader coverage)
            result = self._hash_api(url)
            if result is not None:
                return result

            return FeedResult(
                feed_name=self.name,
                matched=False,
                details="Not found in Lookup or Hash API",
            )

        except requests.exceptions.RequestException as e:
            return FeedResult(
                feed_name=self.name,
                matched=False,
                details=f"Request failed: {e}",
            )
