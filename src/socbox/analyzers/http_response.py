"""HTTP response analysis for phishing detection."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests
import tldextract

from socbox.analyzers.base import BaseAnalyzer
from socbox.dns_util import request_with_doh_fallback
from socbox.models import AnalyzerResult, AnalyzerStatus, Finding


def _is_trivial_redirect(from_url: str, to_url: str) -> bool:
    """Return True if the redirect is a routine, non-suspicious hop.

    Covers two common cases that should not be flagged:
      1. HTTP → HTTPS upgrade on the same host and path.
      2. Bare domain ↔ ``www.`` subdomain on the same registered domain
         and path (e.g. ``twitch.tv`` → ``www.twitch.tv``).

    These may be combined (``http://twitch.tv`` → ``https://www.twitch.tv``).

    Args:
        from_url: The URL before the redirect.
        to_url: The URL after the redirect.

    Returns:
        True when the hop is trivial and should be ignored.
    """
    a = urlparse(from_url)
    b = urlparse(to_url)

    # Normalise paths so a trailing slash doesn't cause a false mismatch
    path_a = a.path.rstrip("/") or "/"
    path_b = b.path.rstrip("/") or "/"

    if path_a != path_b or a.query != b.query:
        return False

    host_a = a.hostname or ""
    host_b = b.hostname or ""

    # Strip optional "www." prefix for comparison
    bare_a = host_a.removeprefix("www.")
    bare_b = host_b.removeprefix("www.")

    if bare_a.lower() != bare_b.lower():
        return False

    # At this point hosts differ only by www. prefix (or are identical)
    # and the path + query are the same.  Accept any scheme combination.
    return True


class HTTPResponseAnalyzer(BaseAnalyzer):
    """Analyze HTTP response behavior for phishing indicators.

    Checks redirect chains, suspicious headers, and content type mismatches.
    """

    name = "HTTP Response Analysis"
    weight = 15.0

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Fetch the URL and analyze HTTP response characteristics.

        Args:
            url: The URL to analyze.
            config: The loaded configuration dictionary.

        Returns:
            AnalyzerResult with HTTP response findings.
        """
        timeout = config.get("requests", {}).get("timeout", 10)
        user_agent = config.get("requests", {}).get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        max_redirects = config.get("requests", {}).get("max_redirects", 10)
        verify_ssl = config.get("requests", {}).get("verify_ssl", False)

        findings: list[Finding] = []

        try:
            session = requests.Session()
            session.max_redirects = max_redirects
            # stream=True so the (potentially hostile, unbounded) response body
            # is never downloaded - this analyzer only inspects headers, the
            # redirect history, and the final URL.
            response = request_with_doh_fallback(
                "GET",
                url,
                session=session,
                headers={"User-Agent": user_agent},
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
                stream=True,
            )
            response.close()
        except requests.exceptions.TooManyRedirects:
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.COMPLETED,
                score=40.0,
                max_weight=self.weight,
                findings=[
                    Finding(
                        description=f"Excessive redirects (>{max_redirects})",
                        score_contribution=40.0,
                        severity="high",
                    )
                ],
            )
        except requests.exceptions.RequestException as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.ERROR,
                score=0.0,
                max_weight=self.weight,
                error_message=f"HTTP request failed: {e}",
            )

        # Analyze redirect chain
        redirect_findings = self._check_redirect_chain(response, url)
        findings.extend(redirect_findings)

        # Store redirect chain as a special finding for the scanner to extract.
        # Filter out trivial hops (http→https, bare→www) so only
        # meaningful redirects surface in the UI.
        if response.history:
            raw_chain = [r.url for r in response.history] + [response.url]
            chain: list[str] = [raw_chain[0]]
            for hop in raw_chain[1:]:
                if not _is_trivial_redirect(chain[-1], hop):
                    chain.append(hop)
                else:
                    # Replace the previous endpoint with the upgraded URL
                    chain[-1] = hop

            # Only record the chain if there are real (non-trivial) hops
            if len(chain) > 1:
                findings.append(
                    Finding(
                        description=f"Redirect chain: {' -> '.join(chain)}",
                        score_contribution=0.0,
                        severity="info",
                    )
                )

        # Analyze headers
        header_findings = self._check_suspicious_headers(response)
        findings.extend(header_findings)

        # Content type check
        ct_finding = self._check_content_type(response)
        if ct_finding:
            findings.append(ct_finding)

        score = min(100.0, sum(f.score_contribution for f in findings))

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    def _check_redirect_chain(
        self, response: requests.Response, original_url: str
    ) -> list[Finding]:
        """Analyze the redirect chain for suspicious behavior.

        Trivial hops (http→https upgrades, bare-domain ↔ www) are
        filtered out before any scoring so they don't inflate redirect
        counts or trigger false-positive cross-domain findings.

        Args:
            response: The final HTTP response (after redirects).
            original_url: The URL that was originally requested.

        Returns:
            List of redirect-related findings.
        """
        findings: list[Finding] = []
        history = response.history

        if not history:
            return findings

        # Build a de-trivialised chain of meaningful hops
        raw_chain = [original_url] + [r.url for r in history] + [response.url]
        chain: list[str] = [raw_chain[0]]
        for hop in raw_chain[1:]:
            if not _is_trivial_redirect(chain[-1], hop):
                chain.append(hop)
            else:
                chain[-1] = hop

        # Number of *meaningful* redirects (hops minus the origin)
        num_redirects = len(chain) - 1

        if num_redirects > 3:
            findings.append(
                Finding(
                    description=f"Long redirect chain ({num_redirects} redirects)",
                    score_contribution=15.0,
                    severity="medium",
                )
            )

        # Check for cross-domain redirects (using meaningful endpoints)
        if num_redirects >= 1:
            original_domain = tldextract.extract(chain[0]).registered_domain
            final_domain = tldextract.extract(chain[-1]).registered_domain

            if original_domain and final_domain and original_domain != final_domain:
                findings.append(
                    Finding(
                        description=(
                            f"Cross-domain redirect: {original_domain} -> {final_domain}"
                        ),
                        score_contribution=20.0,
                        severity="high",
                    )
                )

        # Check for protocol downgrade (HTTPS -> HTTP) across all raw hops
        for i, r in enumerate(history):
            next_url = history[i + 1].url if i + 1 < len(history) else response.url
            if urlparse(r.url).scheme == "https" and urlparse(next_url).scheme == "http":
                findings.append(
                    Finding(
                        description="Protocol downgrade detected (HTTPS -> HTTP)",
                        score_contribution=25.0,
                        severity="high",
                    )
                )
                break

        return findings

    def _check_suspicious_headers(self, response: requests.Response) -> list[Finding]:
        """Check response headers for suspicious patterns.

        Args:
            response: The HTTP response to inspect.

        Returns:
            List of header-related findings.
        """
        findings: list[Finding] = []
        headers = response.headers

        # Missing security headers on a page that serves HTML
        content_type = headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            if "X-Frame-Options" not in headers and "Content-Security-Policy" not in headers:
                findings.append(
                    Finding(
                        description="Missing X-Frame-Options and CSP headers (clickjacking risk)",
                        score_contribution=5.0,
                        severity="info",
                    )
                )

        # Check for suspicious server headers
        server = headers.get("Server", "").lower()
        if any(kw in server for kw in ["nginx", "apache"]) and "x-powered-by" in headers:
            powered_by = headers["x-powered-by"].lower()
            if "php" in powered_by:
                findings.append(
                    Finding(
                        description=f"Server exposes technology stack: {headers['x-powered-by']}",
                        score_contribution=3.0,
                        severity="info",
                    )
                )

        return findings

    def _check_content_type(self, response: requests.Response) -> Finding | None:
        """Check for content type mismatches and executable downloads.

        Args:
            response: The HTTP response to inspect.

        Returns:
            Finding if content type is unexpected for a web page.
        """
        content_type = response.headers.get("Content-Type", "").lower()
        ct_base = content_type.split(";")[0].strip()

        # URL looks like a webpage but serves non-HTML content
        if response.url.endswith((".html", ".htm", "/")) and "text/html" not in content_type:
            if content_type and "application/octet-stream" in content_type:
                return Finding(
                    description=(
                        f"Content-type mismatch: URL appears to be HTML "
                        f"but serves '{content_type}'"
                    ),
                    score_contribution=15.0,
                    severity="medium",
                )

        # Flag executable/binary download regardless of URL pattern
        executable_types = {
            "application/octet-stream",
            "application/x-msdownload",
            "application/x-executable",
            "application/x-msi",
            "application/vnd.microsoft.portable-executable",
            "application/x-dosexec",
        }
        if ct_base in executable_types:
            return Finding(
                description=f"URL serves executable download: {ct_base}",
                score_contribution=15.0,
                severity="medium",
            )

        return None
