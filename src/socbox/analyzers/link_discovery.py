"""Active link discovery analyzer for SOC Box.

Uses Playwright to find and click sign-in/login buttons on the landing page,
then inspects the destination for credential harvesting indicators.  This
catches phishing pages that hide harvesters behind seemingly benign landing
pages (e.g. a blog with a fake "Sign in" button that leads to a Google
credential stealer).
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

import tldextract
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

from socbox.analyzers.base import BaseAnalyzer
from socbox.browser import create_context, launch_browser, navigate_with_bypass
from socbox.models import AnalyzerResult, AnalyzerStatus, DiscoveredLink, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_LINKS_TO_FOLLOW = 3
_CLICK_TIMEOUT_MS = 5000
_NAV_TIMEOUT_MS = 15000

# Text patterns (case-insensitive) that suggest an auth-related clickable.
_AUTH_TEXT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bsign\s*in\b",
        r"\blog\s*in\b",
        r"\blogin\b",
        r"\bmy\s*account\b",
        r"\bcreate\s*account\b",
        r"\bregister\b",
        r"\bauthenticate\b",
        r"\bverify\b",
        r"\bget\s*started\b",
    ]
]

# href patterns that hint at auth destinations.
_AUTH_HREF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"/sign[_-]?in",
        r"/log[_-]?in",
        r"/login",
        r"/auth",
        r"/account",
        r"/oauth",
        r"/sso",
    ]
]

# Legitimate auth domains that should NOT be flagged - real sign-in pages.
_SAFE_AUTH_DOMAINS = frozenset({
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "appleid.apple.com",
    "www.facebook.com",
    "github.com",
    "auth0.com",
    "login.yahoo.com",
    "signin.aws.amazon.com",
    "id.atlassian.com",
})

class LinkDiscoveryAnalyzer(BaseAnalyzer):
    """Discover and follow auth-related links to detect hidden credential harvesters.

    Loads the page in headless Chromium, finds buttons/links that look like
    sign-in entry points, clicks each one, and inspects the destination for
    phishing indicators such as cross-domain redirects, password fields, and
    brand impersonation.
    """

    name = "Link Discovery Analysis"
    weight = 15.0

    def __init__(self) -> None:
        """Initialize the analyzer with an empty discovered links list."""
        self.last_discovered_links: list[DiscoveredLink] = []

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Run active link discovery on the given URL.

        Args:
            url: The URL to analyze.
            config: The loaded SOC Box configuration dictionary.

        Returns:
            AnalyzerResult with findings from link click-through analysis.
        """
        self.last_discovered_links = []
        brands = [
            tldextract.extract(b).domain.lower()
            for b in config.get("brands", [])
        ]
        source_domain = tldextract.extract(url).registered_domain.lower()

        try:
            candidates, discovered, findings = self._run_browser_discovery(
                url, source_domain, brands, config, browser=browser,
            )
        except Exception as exc:
            logger.error("Link discovery failed for %s: %s", url, exc)
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.ERROR,
                score=0.0,
                max_weight=self.weight,
                error_message=f"Link discovery failed: {exc}",
            )

        self.last_discovered_links = discovered

        if not candidates:
            findings.append(Finding(
                description="No auth-related links or buttons detected on page",
                score_contribution=0.0,
                severity="info",
            ))

        score = min(100.0, sum(f.score_contribution for f in findings))

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Browser session
    # ------------------------------------------------------------------

    def _run_browser_discovery(
        self,
        url: str,
        source_domain: str,
        brands: list[str],
        config: dict[str, Any],
        *,
        browser: Any = None,
    ) -> tuple[list[dict], list[DiscoveredLink], list[Finding]]:
        """Launch Playwright, find auth links, click them, inspect destinations.

        Args:
            url: The landing page URL.
            source_domain: The registered domain of the landing page.
            brands: List of brand domain names from config.
            config: Full config dict.
            browser: Optional shared Playwright Browser instance. When
                provided, contexts are created from it instead of launching
                a new browser.

        Returns:
            Tuple of (candidate_elements, discovered_links, findings).
        """
        candidates: list[dict] = []
        discovered: list[DiscoveredLink] = []
        findings: list[Finding] = []

        own_browser = browser is None

        if own_browser:
            pw_ctx = sync_playwright().start()
            browser = launch_browser(pw_ctx, url)

        try:
            # --- Phase 1: find candidate elements ---
            context = create_context(browser)
            page = context.new_page()

            status = navigate_with_bypass(page, url, timeout_ms=_NAV_TIMEOUT_MS)
            if status == 0:
                context.close()
                if own_browser:
                    browser.close()
                    pw_ctx.stop()
                return [], [], [Finding(
                    description="Page load timed out during link discovery",
                    score_contribution=0.0,
                    severity="info",
                )]

            candidates = self._find_auth_candidates(page)
            context.close()

            if not candidates:
                if own_browser:
                    browser.close()
                    pw_ctx.stop()
                return [], [], []

            logger.info(
                "Link discovery found %d auth candidate(s) on %s",
                len(candidates), url,
            )

            # --- Phase 2: click each candidate in isolation ---
            for cand in candidates[:_MAX_LINKS_TO_FOLLOW]:
                link, finding = self._follow_candidate(
                    browser, url, cand, source_domain, brands,
                )
                if link is not None:
                    discovered.append(link)
                if finding is not None:
                    findings.append(finding)

        finally:
            if own_browser:
                browser.close()
                pw_ctx.stop()

        return candidates, discovered, findings

    # ------------------------------------------------------------------
    # Candidate detection
    # ------------------------------------------------------------------

    def _find_auth_candidates(self, page: object) -> list[dict]:
        """Find clickable elements on the page that look like auth entry points.

        Args:
            page: The Playwright page object.

        Returns:
            List of dicts with 'text', 'href', and 'selector' keys.
        """
        raw = page.evaluate("""() => {
            const results = [];
            const seen = new Set();

            // Collect <a> and <button> elements plus role="button" / role="link"
            const selectors = [
                'a[href]',
                'button',
                '[role="button"]',
                '[role="link"]',
                'input[type="submit"]',
                'input[type="button"]',
            ];

            for (const sel of selectors) {
                for (const el of document.querySelectorAll(sel)) {
                    const rawText = (el.textContent ?? el.value ?? '');
                    const text = String(rawText).trim();
                    if (!text || text.length > 100) continue;

                    const href = el.getAttribute('href') || '';
                    const key = text.toLowerCase() + '|' + href;
                    if (seen.has(key)) continue;
                    seen.add(key);

                    // Build a unique CSS selector for re-finding this element
                    let selector = '';
                    if (el.id) {
                        selector = '#' + CSS.escape(el.id);
                    } else if (href && el.tagName === 'A') {
                        selector = `a[href="${CSS.escape(href)}"]`;
                    }

                    results.push({
                        text: text.substring(0, 80),
                        href: href,
                        tag: el.tagName.toLowerCase(),
                        selector: selector,
                    });
                }
            }
            return results;
        }""")

        # Filter to auth-related candidates
        candidates = []
        for item in raw:
            text = item.get("text", "")
            href = item.get("href", "")

            text_match = any(pat.search(text) for pat in _AUTH_TEXT_PATTERNS)
            href_match = any(pat.search(href) for pat in _AUTH_HREF_PATTERNS)

            if text_match or href_match:
                candidates.append(item)

        return candidates

    # ------------------------------------------------------------------
    # Follow a single candidate
    # ------------------------------------------------------------------

    def _follow_candidate(
        self,
        browser: object,
        source_url: str,
        candidate: dict,
        source_domain: str,
        brands: list[str],
    ) -> tuple[DiscoveredLink | None, Finding | None]:
        """Click a candidate element and inspect the destination.

        Opens a fresh browser context, navigates to the source URL, clicks
        the candidate, and analyzes where it leads.

        Args:
            browser: The Playwright browser instance.
            source_url: The original landing page URL.
            candidate: Dict with 'text', 'href', 'selector', 'tag' keys.
            source_domain: Registered domain of the source page.
            brands: List of brand names to check for impersonation.

        Returns:
            Tuple of (DiscoveredLink or None, Finding or None).
        """
        elem_text = candidate["text"]
        href = candidate.get("href", "")

        # If the href is a full URL, we can inspect it directly
        # without clicking (faster and safer).
        destination_url = ""
        if href.startswith(("http://", "https://")):
            destination_url = href
        elif href.startswith("/") and href != "/":
            # Relative path - resolve against source
            parsed = urlparse(source_url)
            destination_url = f"{parsed.scheme}://{parsed.netloc}{href}"

        # If we got a destination from href, inspect it directly
        if destination_url:
            return self._inspect_destination(
                browser, source_url, destination_url, elem_text,
                source_domain, brands,
            )

        # Otherwise, actually click the element in a fresh context
        context = create_context(browser)
        page = context.new_page()

        try:
            navigate_with_bypass(page, source_url, timeout_ms=_NAV_TIMEOUT_MS)

            # Try to find and click the element
            clicked = False
            selector = candidate.get("selector", "")
            if selector:
                try:
                    page.click(selector, timeout=_CLICK_TIMEOUT_MS)
                    clicked = True
                except Exception:
                    pass

            if not clicked:
                # Fallback: find by text content
                try:
                    page.get_by_text(elem_text, exact=False).first.click(
                        timeout=_CLICK_TIMEOUT_MS,
                    )
                    clicked = True
                except Exception:
                    pass

            if not clicked:
                logger.debug("Could not click candidate '%s'", elem_text)
                context.close()
                return None, None

            # Wait for navigation
            page.wait_for_timeout(3000)
            destination_url = page.url

        except PlaywrightTimeout:
            logger.debug("Click timed out for '%s'", elem_text)
            context.close()
            return None, None
        except Exception as exc:
            logger.debug("Click failed for '%s': %s", elem_text, exc)
            context.close()
            return None, None

        # Check if a new tab/popup was opened
        pages = context.pages
        if len(pages) > 1:
            destination_url = pages[-1].url

        result = self._inspect_destination(
            browser, source_url, destination_url, elem_text,
            source_domain, brands, page=pages[-1] if len(pages) > 1 else page,
        )
        context.close()
        return result

    # ------------------------------------------------------------------
    # Destination inspection
    # ------------------------------------------------------------------

    def _inspect_destination(
        self,
        browser: object,
        source_url: str,
        destination_url: str,
        elem_text: str,
        source_domain: str,
        brands: list[str],
        page: object | None = None,
    ) -> tuple[DiscoveredLink | None, Finding | None]:
        """Inspect a destination URL for phishing indicators.

        Args:
            browser: The Playwright browser instance.
            source_url: The original landing page URL.
            destination_url: Where the click led.
            elem_text: The text of the clicked element.
            source_domain: Registered domain of the source page.
            brands: List of brand names to check.
            page: Optional already-loaded Playwright page to inspect.

        Returns:
            Tuple of (DiscoveredLink, Finding) or (None, None) if benign.
        """
        dest_extracted = tldextract.extract(destination_url)
        dest_domain = dest_extracted.registered_domain.lower()
        dest_hostname = (
            f"{dest_extracted.subdomain}.{dest_extracted.domain}.{dest_extracted.suffix}"
            if dest_extracted.subdomain
            else f"{dest_extracted.domain}.{dest_extracted.suffix}"
        ).lower()

        # Skip if destination is the same page
        if dest_domain == source_domain:
            return None, None

        # Known-safe auth provider - report as info, not a threat
        if dest_hostname in _SAFE_AUTH_DOMAINS:
            finding = Finding(
                description=(
                    f"Auth link \"{elem_text}\" leads to legitimate provider: "
                    f"{dest_hostname}"
                ),
                score_contribution=0.0,
                severity="info",
            )
            return None, finding
        if not destination_url.startswith(("http://", "https://")):
            return None, None

        is_cross_domain = dest_domain != source_domain

        # Load the destination page if we don't already have it
        has_credential_form = False
        brand_detected = ""
        own_context = False

        if page is None:
            context = create_context(browser)
            page = context.new_page()
            own_context = True
            status = navigate_with_bypass(
                page, destination_url, timeout_ms=_NAV_TIMEOUT_MS,
            )
            if status == 0:
                logger.debug("Destination load timed out: %s", destination_url)
                context.close()
                # Still report the cross-domain redirect even if we can't load it
                link = DiscoveredLink(
                    element_text=elem_text,
                    source_url=source_url,
                    destination_url=destination_url,
                    has_credential_form=False,
                    is_cross_domain=is_cross_domain,
                    brand_detected="",
                )
                finding = Finding(
                    description=(
                        f"Auth link \"{elem_text}\" leads to cross-domain URL "
                        f"(destination timed out): {destination_url}"
                    ),
                    score_contribution=15.0,
                    severity="medium",
                )
                return link, finding

        # Check for password fields
        try:
            has_credential_form = page.evaluate("""() => {
                const pwFields = document.querySelectorAll('input[type="password"]');
                const credNames = ['username', 'email', 'user',
                    'login', 'password', 'passwd', 'identifier'];
                const namedInputs = document.querySelectorAll('input[name]');
                let hasCred = pwFields.length > 0;
                for (const inp of namedInputs) {
                    if (credNames.includes(inp.name.toLowerCase())) {
                        hasCred = true;
                        break;
                    }
                }
                return hasCred;
            }""")
        except Exception:
            has_credential_form = False

        # Check for brand impersonation on destination
        try:
            page_text = page.evaluate(
                "() => (document.title + ' ' + "
                "document.body.innerText).toLowerCase()"
                ".substring(0, 5000)"
            )
            dest_base_domain = dest_extracted.domain.lower()
            for brand in brands:
                if brand == dest_base_domain:
                    continue  # This IS the brand's domain
                if brand in page_text:
                    brand_detected = brand
                    break
        except Exception:
            pass

        if own_context:
            context.close()

        # Build result
        link = DiscoveredLink(
            element_text=elem_text,
            source_url=source_url,
            destination_url=destination_url,
            has_credential_form=has_credential_form,
            is_cross_domain=is_cross_domain,
            brand_detected=brand_detected,
        )

        # Score based on severity
        finding = self._build_finding(link)

        return link, finding

    # ------------------------------------------------------------------
    # Finding generation
    # ------------------------------------------------------------------

    def _build_finding(self, link: DiscoveredLink) -> Finding:
        """Generate a Finding from a DiscoveredLink based on indicator severity.

        Args:
            link: The discovered link with inspection results.

        Returns:
            A Finding with appropriate severity and score contribution.
        """
        flags: list[str] = []
        if link.is_cross_domain:
            flags.append("cross-domain")
        if link.has_credential_form:
            flags.append("credential form")
        if link.brand_detected:
            flags.append(f"brand: {link.brand_detected}")

        flag_str = ", ".join(flags) if flags else "no suspicious flags"

        # Critical: cross-domain + credential form
        if link.is_cross_domain and link.has_credential_form:
            return Finding(
                description=(
                    f"Auth link \"{link.element_text}\" leads to cross-domain "
                    f"credential harvester: {link.destination_url} [{flag_str}]"
                ),
                score_contribution=35.0,
                severity="critical",
            )

        # High: cross-domain + brand impersonation
        if link.is_cross_domain and link.brand_detected:
            return Finding(
                description=(
                    f"Auth link \"{link.element_text}\" leads to cross-domain "
                    f"page impersonating {link.brand_detected}: "
                    f"{link.destination_url} [{flag_str}]"
                ),
                score_contribution=25.0,
                severity="high",
            )

        # Medium: cross-domain auth link
        if link.is_cross_domain:
            return Finding(
                description=(
                    f"Auth link \"{link.element_text}\" leads to cross-domain "
                    f"destination: {link.destination_url} [{flag_str}]"
                ),
                score_contribution=15.0,
                severity="medium",
            )

        # Low: same-domain credential form (unusual pattern)
        if link.has_credential_form:
            return Finding(
                description=(
                    f"Auth link \"{link.element_text}\" leads to credential "
                    f"form: {link.destination_url} [{flag_str}]"
                ),
                score_contribution=10.0,
                severity="low",
            )

        # Info: link found but nothing overtly suspicious
        return Finding(
            description=(
                f"Auth link \"{link.element_text}\" leads to: "
                f"{link.destination_url} [{flag_str}]"
            ),
            score_contribution=0.0,
            severity="info",
        )
