"""URL lexical analysis for phishing detection."""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any
from urllib.parse import unquote, urlparse

import tldextract
from Levenshtein import distance as levenshtein_distance

from iris.analyzers.base import BaseAnalyzer
from iris.models import AnalyzerResult, AnalyzerStatus, Finding


class URLLexicalAnalyzer(BaseAnalyzer):
    """Analyze the URL string itself for phishing indicators.

    Checks for IP-based URLs, typosquatting, excessive subdomains,
    URL shorteners, encoded characters, suspicious TLDs, and path patterns.
    """

    name = "URL Lexical Analysis"
    weight = 20.0

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Run all lexical checks against the URL.

        Args:
            url: The URL to analyze.
            config: The loaded configuration dictionary.

        Returns:
            AnalyzerResult with lexical findings.
        """
        findings: list[Finding] = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = tldextract.extract(url)

        checks = [
            self._check_ip_based_url(hostname),
            self._check_excessive_subdomains(extracted),
            self._check_url_shortener(hostname, config),
            self._check_encoded_characters(url),
            self._check_suspicious_tld(extracted, config),
            self._check_typosquatting(extracted, config),
            self._check_at_symbol(url),
            self._check_excessive_length(url),
            self._check_suspicious_path(parsed.path),
            self._check_many_hyphens(hostname),
            self._check_homograph(hostname),
        ]

        for result in checks:
            if result is not None:
                if isinstance(result, list):
                    findings.extend(result)
                else:
                    findings.append(result)

        score = min(100.0, sum(f.score_contribution for f in findings))

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    def _check_ip_based_url(self, hostname: str) -> Finding | None:
        """Check if the URL uses a raw IP address instead of a domain.

        Args:
            hostname: The hostname portion of the URL.

        Returns:
            Finding if the hostname is an IP address.
        """
        try:
            ip_address(hostname)
            return Finding(
                description=f"URL uses raw IP address: {hostname}",
                score_contribution=30.0,
                severity="high",
            )
        except ValueError:
            return None

    def _check_excessive_subdomains(self, extracted: tldextract.ExtractResult) -> Finding | None:
        """Check for excessive subdomain depth.

        Args:
            extracted: The tldextract result.

        Returns:
            Finding if subdomain depth exceeds 3.
        """
        if not extracted.subdomain:
            return None
        parts = extracted.subdomain.split(".")
        if len(parts) > 3:
            return Finding(
                description=(
                    f"Excessive subdomain depth ({len(parts)} levels):"
                    f" {extracted.subdomain}"
                ),
                score_contribution=20.0,
                severity="medium",
            )
        return None

    def _check_url_shortener(self, hostname: str, config: dict[str, Any]) -> Finding | None:
        """Check if the URL uses a known URL shortener.

        Args:
            hostname: The hostname to check.
            config: Configuration with shortener list.

        Returns:
            Finding if hostname matches a known shortener.
        """
        shorteners = config.get("url_shorteners", [])
        if hostname.lower() in [s.lower() for s in shorteners]:
            return Finding(
                description=f"URL shortener detected: {hostname}",
                score_contribution=15.0,
                severity="medium",
            )
        return None

    def _check_encoded_characters(self, url: str) -> Finding | None:
        """Check for percent-encoded characters that may hide the real URL.

        Args:
            url: The full URL string.

        Returns:
            Finding if suspicious encoding is detected.
        """
        decoded = unquote(url)
        encoded_count = url.count("%")
        if encoded_count > 3 and decoded != url:
            return Finding(
                description=f"URL contains {encoded_count} percent-encoded characters",
                score_contribution=15.0,
                severity="medium",
            )
        return None

    def _check_suspicious_tld(
        self, extracted: tldextract.ExtractResult, config: dict[str, Any]
    ) -> Finding | None:
        """Check if the domain uses a suspicious TLD.

        Args:
            extracted: The tldextract result.
            config: Configuration with suspicious TLD list.

        Returns:
            Finding if the TLD is on the suspicious list.
        """
        suspicious_tlds = config.get("suspicious_tlds", [])
        tld = f".{extracted.suffix}"
        if tld in suspicious_tlds:
            return Finding(
                description=f"Suspicious TLD detected: {tld}",
                score_contribution=15.0,
                severity="medium",
            )
        return None

    def _check_typosquatting(
        self, extracted: tldextract.ExtractResult, config: dict[str, Any]
    ) -> Finding | None:
        """Check if the domain is a typosquat of a known brand.

        Uses Levenshtein distance to detect domains that are close
        to but not exactly matching well-known brands.

        Args:
            extracted: The tldextract result.
            config: Configuration with brand list.

        Returns:
            Finding if the domain is suspiciously close to a brand.
        """
        brands = config.get("brands", [])
        domain = extracted.domain.lower()

        for brand_fqdn in brands:
            brand_extracted = tldextract.extract(brand_fqdn)
            brand_name = brand_extracted.domain.lower()

            # Skip exact matches — that's the real brand
            if domain == brand_name:
                continue

            dist = levenshtein_distance(domain, brand_name)
            if dist <= 2 and len(domain) >= 4:
                return Finding(
                    description=(
                        f"Possible typosquatting: '{domain}' is {dist} edit(s) "
                        f"away from '{brand_name}'"
                    ),
                    score_contribution=35.0,
                    severity="high",
                )

        return None

    def _check_at_symbol(self, url: str) -> Finding | None:
        """Check for @ symbol in URL which can disguise the real destination.

        Args:
            url: The full URL string.

        Returns:
            Finding if @ is present in the URL.
        """
        parsed = urlparse(url)
        if "@" in (parsed.netloc or ""):
            return Finding(
                description="URL contains @ symbol, which can disguise the real destination",
                score_contribution=25.0,
                severity="high",
            )
        return None

    def _check_excessive_length(self, url: str) -> Finding | None:
        """Check for excessively long URLs often used in phishing.

        Args:
            url: The full URL string.

        Returns:
            Finding if URL exceeds 100 characters.
        """
        if len(url) > 100:
            return Finding(
                description=f"Excessively long URL ({len(url)} characters)",
                score_contribution=10.0,
                severity="low",
            )
        return None

    def _check_suspicious_path(self, path: str) -> Finding | None:
        """Check for path patterns common in phishing URLs.

        Args:
            path: The URL path component.

        Returns:
            Finding if suspicious path patterns are detected.
        """
        suspicious_patterns = [
            r"/login",
            r"/signin",
            r"/verify",
            r"/secure",
            r"/account",
            r"/update",
            r"/confirm",
            r"/banking",
            r"/password",
            r"/credential",
        ]
        path_lower = path.lower()
        matches = [p for p in suspicious_patterns if re.search(p, path_lower)]
        if matches:
            return Finding(
                description=f"Suspicious path keywords: {', '.join(matches)}",
                score_contribution=10.0,
                severity="low",
            )
        return None

    def _check_many_hyphens(self, hostname: str) -> Finding | None:
        """Check for excessive hyphens in the hostname.

        Args:
            hostname: The hostname to check.

        Returns:
            Finding if hostname contains 3+ hyphens.
        """
        if hostname.count("-") >= 3:
            return Finding(
                description=f"Hostname contains {hostname.count('-')} hyphens",
                score_contribution=15.0,
                severity="medium",
            )
        return None

    def _check_homograph(self, hostname: str) -> Finding | None:
        """Check for non-ASCII characters that could be homograph attacks.

        Args:
            hostname: The hostname to check.

        Returns:
            Finding if non-ASCII characters are detected.
        """
        try:
            hostname.encode("ascii")
        except UnicodeEncodeError:
            return Finding(
                description="Hostname contains non-ASCII characters (possible homograph attack)",
                score_contribution=30.0,
                severity="high",
            )

        # Punycode/IDN labels (xn--) are ASCII on the wire but render as
        # non-ASCII in the browser — a common homograph vector the plain
        # non-ASCII check above misses (e.g. xn--pple-43d.com → "аpple.com").
        if any(label.startswith("xn--") for label in hostname.lower().split(".")):
            return Finding(
                description=(
                    "Hostname uses punycode/IDN encoding (xn--), "
                    "a possible homograph attack"
                ),
                score_contribution=30.0,
                severity="high",
            )
        return None
