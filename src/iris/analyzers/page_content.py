"""Page content analysis for phishing detection."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from iris.analyzers.base import BaseAnalyzer
from iris.models import AnalyzerResult, AnalyzerStatus, Finding

logger = logging.getLogger(__name__)


class PageContentAnalyzer(BaseAnalyzer):
    """Analyze the HTML page content for phishing indicators.

    Detects login forms, brand keyword mismatches, hidden form fields,
    and favicon fingerprinting.
    """

    name = "Page Content Analysis"
    weight = 15.0

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Fetch and parse the page content for phishing indicators.

        Args:
            url: The URL to analyze.
            config: The loaded configuration dictionary.

        Returns:
            AnalyzerResult with page content findings.
        """
        timeout = config.get("requests", {}).get("timeout", 10)
        user_agent = config.get("requests", {}).get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        verify_ssl = config.get("requests", {}).get("verify_ssl", False)

        extra_findings: list[Finding] = []
        html_text = ""
        use_browser = False
        # Captured for downstream threat classification (see iris.classification).
        self.page_text: str = ""
        self.scripts: list[str] = []

        try:
            response = requests.get(
                url,
                headers={"User-Agent": user_agent},
                timeout=timeout,
                verify=verify_ssl,
            )
        except requests.exceptions.RequestException:
            response = None
            use_browser = True

        if response is not None:
            blocked_finding = self._detect_security_block(response)
            if blocked_finding is not None:
                extra_findings.append(blocked_finding)
                use_browser = True
            elif response.status_code >= 400:
                use_browser = True
            else:
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type:
                    return AnalyzerResult(
                        analyzer_name=self.name,
                        status=AnalyzerStatus.COMPLETED,
                        score=0.0,
                        max_weight=self.weight,
                        findings=[
                            Finding(
                                description="Response is not HTML, skipping content analysis",
                                score_contribution=0.0,
                                severity="info",
                            )
                        ],
                    )
                html_text = response.text

        # Fallback: use a real browser to bypass Cloudflare / bot protection
        if use_browser:
            logger.info("Using browser fallback for page content: %s", url)
            html_text = self._fetch_with_browser(url, browser=browser)
            if not html_text:
                # Browser also failed — return what we have
                if extra_findings:
                    score = min(100.0, sum(f.score_contribution for f in extra_findings))
                    return AnalyzerResult(
                        analyzer_name=self.name,
                        status=AnalyzerStatus.COMPLETED,
                        score=score,
                        max_weight=self.weight,
                        findings=extra_findings,
                    )
                return AnalyzerResult(
                    analyzer_name=self.name,
                    status=AnalyzerStatus.ERROR,
                    score=0.0,
                    max_weight=self.weight,
                    error_message="Failed to fetch page via requests and browser",
                )

        soup = BeautifulSoup(html_text, "html.parser")
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Capture visible text + scripts so the classifier can spot techniques
        # (ClickFix, encoded commands, pastejacking, drainers, captcha gating).
        self.page_text = soup.get_text(" ", strip=True)[:200000]
        scripts: list[str] = []
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                scripts.append(src)
            body = tag.string or tag.get_text()
            if body and body.strip():
                scripts.append(body[:50000])
        self.scripts = scripts

        findings: list[Finding] = list(extra_findings)

        checks = [
            self._detect_login_forms(soup),
            self._detect_brand_mismatch(soup, hostname, config),
            self._detect_hidden_fields(soup),
            self._detect_password_input(soup),
            self._detect_form_action_mismatch(soup, hostname),
            self._detect_data_exfil_indicators(soup),
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

    @staticmethod
    def _detect_security_block(response: requests.Response) -> Finding | None:
        """Detect if the HTTP response is a security-provider phishing block.

        Checks for known interstitial pages from Cloudflare, Google Safe
        Browsing, and similar services that flag the URL as malicious.

        Args:
            response: The HTTP response object.

        Returns:
            A Finding if a security block was detected, otherwise None.
        """
        if response.status_code not in (403, 503):
            return None

        body = response.text.lower()

        # Cloudflare phishing/malware block
        if "suspected phishing" in body and "cloudflare" in body:
            return Finding(
                description=(
                    "Cloudflare blocked this page as suspected phishing "
                    f"(HTTP {response.status_code})"
                ),
                score_contribution=30.0,
                severity="high",
            )
        if "suspected malware" in body and "cloudflare" in body:
            return Finding(
                description=(
                    "Cloudflare blocked this page as suspected malware "
                    f"(HTTP {response.status_code})"
                ),
                score_contribution=30.0,
                severity="high",
            )

        # Cloudflare generic security block
        if "cloudflare" in body and ("attention required" in body or "ray id" in body):
            if "phish" in body or "malware" in body or "deceptive" in body:
                return Finding(
                    description=(
                        "Cloudflare security block detected — page flagged "
                        f"as dangerous (HTTP {response.status_code})"
                    ),
                    score_contribution=25.0,
                    severity="high",
                )

        # Google Safe Browsing interstitial
        if "deceptive site" in body or "the site ahead contains" in body:
            return Finding(
                description=(
                    "Browser/proxy blocked this page as deceptive "
                    f"(HTTP {response.status_code})"
                ),
                score_contribution=30.0,
                severity="high",
            )

        return None

    @staticmethod
    def _fetch_with_browser(url: str, *, browser: Any = None) -> str:
        """Fetch page HTML using Playwright with Cloudflare bypass.

        Falls back to a real browser when the ``requests`` library is
        blocked by Cloudflare or other bot-protection systems.

        Args:
            url: The URL to fetch.
            browser: Optional shared Playwright Browser instance. When
                provided, a new context is created from it instead of
                launching a new browser.

        Returns:
            The page's outer HTML, or an empty string on failure.
        """
        from playwright.sync_api import sync_playwright

        from iris.browser import (
            create_context,
            launch_browser,
            navigate_with_bypass,
        )

        own_browser = browser is None

        try:
            if own_browser:
                pw_ctx = sync_playwright().start()
                browser = launch_browser(pw_ctx, url)

            context = create_context(browser)
            page = context.new_page()

            status = navigate_with_bypass(page, url)
            if status == 0:
                context.close()
                if own_browser:
                    browser.close()
                    pw_ctx.stop()
                return ""

            html = page.evaluate(
                "() => document.documentElement.outerHTML"
            )
            context.close()
            if own_browser:
                browser.close()
                pw_ctx.stop()
            return html
        except Exception as exc:
            logger.error("Browser fallback failed for %s: %s", url, exc)
            return ""

    def _detect_login_forms(self, soup: BeautifulSoup) -> Finding | None:
        """Detect login/credential entry forms on the page.

        Args:
            soup: Parsed HTML content.

        Returns:
            Finding if login forms are detected.
        """
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            input_types = {inp.get("type", "text").lower() for inp in inputs}
            input_names = {(inp.get("name") or "").lower() for inp in inputs}

            has_password = "password" in input_types
            has_credential_field = bool(
                input_names & {"username", "email", "user", "login", "password", "passwd"}
            )

            if has_password or has_credential_field:
                return Finding(
                    description="Page contains a login/credential entry form",
                    score_contribution=20.0,
                    severity="medium",
                )

        return None

    def _detect_brand_mismatch(
        self, soup: BeautifulSoup, hostname: str, config: dict[str, Any]
    ) -> Finding | None:
        """Detect brand names in page content that don't match the domain.

        Args:
            soup: Parsed HTML content.
            hostname: The hostname of the URL.
            config: Configuration with brand list.

        Returns:
            Finding if brand mismatch is detected.
        """
        brands = config.get("brands", [])
        extracted = tldextract.extract(hostname)
        site_domain = extracted.domain.lower()

        page_text = soup.get_text(separator=" ").lower()
        title = (soup.title.string or "").lower() if soup.title else ""

        for brand_fqdn in brands:
            brand_name = tldextract.extract(brand_fqdn).domain.lower()

            # Skip if this IS the brand's domain
            if brand_name == site_domain:
                continue

            # Check if brand name appears prominently in title or page text
            brand_in_title = brand_name in title
            brand_count = page_text.count(brand_name)

            if brand_in_title or brand_count >= 3:
                return Finding(
                    description=(
                        f"Brand '{brand_name}' referenced {brand_count}x in page "
                        f"(title match: {brand_in_title}) but domain is '{site_domain}'"
                    ),
                    score_contribution=30.0,
                    severity="high",
                )

        return None

    def _detect_hidden_fields(self, soup: BeautifulSoup) -> Finding | None:
        """Detect suspiciously hidden form fields.

        Args:
            soup: Parsed HTML content.

        Returns:
            Finding if excessive hidden fields are found.
        """
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        # Filter out common legitimate hidden fields (CSRF tokens, etc.)
        suspicious_hidden = [
            inp for inp in hidden_inputs
            if (inp.get("name") or "").lower() not in {"csrf", "csrftoken", "_token", "csrf_token"}
        ]

        if len(suspicious_hidden) > 5:
            return Finding(
                description=f"Page has {len(suspicious_hidden)} hidden form fields",
                score_contribution=10.0,
                severity="low",
            )

        return None

    def _detect_password_input(self, soup: BeautifulSoup) -> Finding | None:
        """Detect password inputs outside of proper form context.

        Args:
            soup: Parsed HTML content.

        Returns:
            Finding if orphaned password fields are found.
        """
        password_inputs = soup.find_all("input", {"type": "password"})
        for pw_input in password_inputs:
            # Check if it's inside a form with an action
            parent_form = pw_input.find_parent("form")
            if parent_form is None:
                return Finding(
                    description="Password input found outside of a form element",
                    score_contribution=15.0,
                    severity="medium",
                )

        return None

    def _detect_form_action_mismatch(
        self, soup: BeautifulSoup, hostname: str
    ) -> Finding | None:
        """Check if form actions point to a different domain.

        Args:
            soup: Parsed HTML content.
            hostname: The hostname of the page.

        Returns:
            Finding if forms submit to external domains.
        """
        site_domain = tldextract.extract(hostname).registered_domain

        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "")
            if action.startswith(("http://", "https://")):
                action_domain = tldextract.extract(action).registered_domain
                if action_domain and site_domain and action_domain != site_domain:
                    return Finding(
                        description=(
                            f"Form submits to external domain: {action_domain} "
                            f"(page is on {site_domain})"
                        ),
                        score_contribution=25.0,
                        severity="high",
                    )

        return None

    def _detect_data_exfil_indicators(self, soup: BeautifulSoup) -> Finding | None:
        """Detect JavaScript patterns that may exfiltrate data.

        Args:
            soup: Parsed HTML content.

        Returns:
            Finding if suspicious JS patterns are detected.
        """
        scripts = soup.find_all("script")
        suspicious_patterns = [
            "document.cookie",
            "localStorage",
            "sessionStorage",
            "XMLHttpRequest",
            "navigator.credentials",
        ]

        for script in scripts:
            script_text = script.string or ""
            matches = [p for p in suspicious_patterns if p in script_text]
            if len(matches) >= 2:
                return Finding(
                    description=f"Inline script accesses sensitive APIs: {', '.join(matches)}",
                    score_contribution=15.0,
                    severity="medium",
                )

        return None
