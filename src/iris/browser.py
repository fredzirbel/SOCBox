"""Shared Playwright browser utilities for IRIS.

Provides a consistent browser launch configuration and Cloudflare phishing
interstitial bypass.  Used by the screenshot module, link discovery analyzer,
and any other component that needs to load pages in a real browser.

Key features:
- Uses system Chrome (``channel='chrome'``) for a legitimate TLS fingerprint.
- Runs headed but with the window off-screen so no GUI is visible.
- Disables Chrome's built-in Safe Browsing to avoid browser-level blocks.
- Detects and automatically bypasses Cloudflare "Suspected Phishing"
  interstitial pages by waiting for the Turnstile challenge to auto-solve,
  then submitting the bypass form.
- Falls back to DoH-based DNS when the system resolver blocks a domain.
"""

from __future__ import annotations

import json
import logging
import random

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
)
from playwright.sync_api import (
    TimeoutError as PlaywrightTimeout,
)

from iris.dns_util import build_chromium_args

logger = logging.getLogger(__name__)

# Realistic Chrome user-agent.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Anti-detection init script injected into every browser context.
# Overrides the most commonly-checked fingerprinting properties so that
# the Linux container looks like a normal Windows desktop browser.
_INIT_SCRIPT = """
    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
    Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
    Object.defineProperty(navigator, 'oscpu', {get: () => undefined});
    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5]
    });
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en']
    });
    Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
    Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});

    // Override User-Agent Client Hints (used by modern fingerprinters)
    if (navigator.userAgentData) {
        Object.defineProperty(navigator, 'userAgentData', {
            get: () => ({
                brands: [
                    {brand: 'Chromium', version: '124'},
                    {brand: 'Google Chrome', version: '124'},
                    {brand: 'Not-A.Brand', version: '99'}
                ],
                mobile: false,
                platform: 'Windows',
                getHighEntropyValues: () => Promise.resolve({
                    architecture: 'x86',
                    bitness: '64',
                    model: '',
                    platform: 'Windows',
                    platformVersion: '15.0.0',
                    uaFullVersion: '124.0.0.0',
                    fullVersionList: [
                        {brand: 'Chromium', version: '124.0.0.0'},
                        {brand: 'Google Chrome', version: '124.0.0.0'}
                    ]
                })
            })
        });
    }

    window.chrome = {runtime: {}};
"""

# Maximum time (ms) to wait for Cloudflare Turnstile to auto-solve.
_TURNSTILE_TIMEOUT_MS = 15000
_TURNSTILE_POLL_MS = 500

# Viewport used by create_context(); human-behavior simulation stays within it.
_VIEWPORT_WIDTH = 1280
_VIEWPORT_HEIGHT = 720

# ---------------------------------------------------------------------------
# Interactive (human-in-the-loop) CAPTCHA solving
# ---------------------------------------------------------------------------
# When enabled, an interactive CAPTCHA the tool cannot auto-pass (reCAPTCHA /
# hCaptcha image challenge, interactive Turnstile) pauses the scan so the
# operator can solve it in the on-screen browser window; analysis resumes
# automatically once the challenge clears.
#
# This is process-global on purpose: it is meant for local / CLI, single-scan
# use where one human is watching one browser. It is NOT for the concurrent
# web server (a remote user cannot click a server-side browser — that needs
# remote browser streaming, e.g. noVNC).
_INTERACTIVE_MODE = False

# How long to wait for a human to solve a challenge before giving up.
_CAPTCHA_SOLVE_TIMEOUT_MS = 180_000  # 3 minutes
_CAPTCHA_POLL_MS = 1000

# Visible-iframe src signatures for interactive CAPTCHA challenge widgets.
# These match the *challenge* surface (the part requiring human input), not
# the tiny always-present anchor/checkbox iframe.
_CAPTCHA_SIGNATURES = {
    "reCAPTCHA": ["recaptcha/api2/bframe", "recaptcha/enterprise/bframe"],
    "hCaptcha": ["hcaptcha.com", "newassets.hcaptcha.com"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com"],
}


def set_interactive_mode(enabled: bool) -> None:
    """Enable or disable human-in-the-loop CAPTCHA solving (process-global).

    Args:
        enabled: True to pause on unsolvable CAPTCHAs for manual solving.
    """
    global _INTERACTIVE_MODE
    _INTERACTIVE_MODE = enabled


def detect_interactive_captcha(page: Page) -> str:
    """Return the provider name of a *visible* interactive CAPTCHA, or ``""``.

    Looks for a sufficiently-large (i.e. actively displayed) iframe whose src
    matches a known challenge-widget signature. The small anchor checkbox and
    hidden challenge frames are ignored via a minimum-size filter.

    Args:
        page: The Playwright page to inspect.

    Returns:
        The provider name (e.g. ``"reCAPTCHA"``) or ``""`` when none is shown.
    """
    sigs_json = json.dumps(_CAPTCHA_SIGNATURES)
    try:
        return page.evaluate(f"""() => {{
            const sigs = {sigs_json};
            const frames = Array.from(document.querySelectorAll('iframe'));
            for (const f of frames) {{
                const src = f.src || '';
                const rect = f.getBoundingClientRect();
                // Skip invisible / anchor-sized frames.
                if (rect.width < 100 || rect.height < 100) continue;
                for (const name in sigs) {{
                    if (sigs[name].some(p => src.includes(p))) return name;
                }}
            }}
            return '';
        }}""") or ""
    except Exception as exc:
        logger.debug("Interactive CAPTCHA detection failed: %s", exc)
        return ""


def wait_for_manual_captcha_solve(page: Page, provider: str) -> bool:
    """Pause the scan while the operator solves a CAPTCHA in the browser window.

    Polls until the visible challenge clears, or until the solve timeout
    elapses. Intended for interactive (on-screen) local runs.

    Args:
        page: The Playwright page showing the challenge.
        provider: Provider name for operator-facing messaging.

    Returns:
        True if the challenge cleared (solved), False on timeout.
    """
    timeout_s = _CAPTCHA_SOLVE_TIMEOUT_MS // 1000
    logger.warning(
        "Interactive %s CAPTCHA detected — waiting up to %ds for manual solve",
        provider, timeout_s,
    )
    # Operator-facing prompt (the visible channel for a CLI run).
    print(
        f"\n[IRIS] {provider} CAPTCHA detected. Solve it in the browser "
        f"window — analysis resumes automatically once it clears "
        f"(waiting up to {timeout_s}s)…",
        flush=True,
    )

    elapsed = 0
    while elapsed < _CAPTCHA_SOLVE_TIMEOUT_MS:
        if not detect_interactive_captcha(page):
            logger.info("CAPTCHA cleared — resuming analysis")
            print("[IRIS] CAPTCHA cleared — resuming analysis.\n", flush=True)
            return True
        page.wait_for_timeout(_CAPTCHA_POLL_MS)
        elapsed += _CAPTCHA_POLL_MS

    logger.warning("CAPTCHA not solved within %ds — continuing", timeout_s)
    print("[IRIS] Timed out waiting for CAPTCHA — continuing analysis.\n", flush=True)
    return False


def launch_browser(pw: Playwright, url: str, *, interactive: bool = False) -> Browser:
    """Launch a browser configured for phishing analysis.

    Uses the system-installed Chrome (headed) to get a real TLS fingerprint
    that passes Cloudflare Turnstile.  Falls back to bundled Chromium if
    system Chrome is unavailable.

    By default the window is pushed off-screen so no GUI is visible. In
    ``interactive`` mode the window is kept on-screen (and the fallback runs
    headed) so a human operator can solve a CAPTCHA the tool cannot.

    Args:
        pw: An active Playwright instance from ``sync_playwright()``.
        url: The URL that will be navigated to (used to build DNS args).
        interactive: When True, keep the browser window visible and on-screen
            for human-in-the-loop CAPTCHA solving.

    Returns:
        A launched Browser instance.
    """
    base_args = build_chromium_args(url)
    base_args.extend([
        "--disable-features=SafeBrowsing,DnsOverHttps",
        "--disable-client-side-phishing-detection",
        "--safebrowsing-disable-download-protection",
    ])

    # Off-screen unless the operator needs to see and click the window.
    chrome_args = list(base_args)
    if not interactive:
        chrome_args.append("--window-position=-9999,-9999")

    # Try system Chrome first (headed)
    try:
        browser = pw.chromium.launch(
            headless=False,
            channel="chrome",
            args=chrome_args,
        )
        logger.debug(
            "Launched system Chrome (headed, %s)",
            "on-screen/interactive" if interactive else "off-screen",
        )
        return browser
    except Exception as exc:
        logger.debug("System Chrome not available: %s", exc)

    # Fallback: bundled Chromium. Must be headed in interactive mode so the
    # operator can actually see and solve the challenge.
    browser = pw.chromium.launch(
        headless=not interactive,
        args=base_args,
    )
    logger.debug(
        "Launched bundled Chromium (%s)",
        "headed/interactive" if interactive else "headless",
    )
    return browser


def create_context(browser: Browser) -> BrowserContext:
    """Create a browser context with anti-fingerprinting protections.

    Args:
        browser: A launched Browser instance.

    Returns:
        A configured BrowserContext.
    """
    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
        user_agent=USER_AGENT,
        locale="en-US",
        timezone_id="America/New_York",
    )
    context.add_init_script(_INIT_SCRIPT)
    return context


def _simulate_human_behavior(page: Page) -> None:
    """Perform brief, bounded human-like interaction on the current page.

    Invisible / score-based challenges (reCAPTCHA v3, Cloudflare Turnstile in
    managed mode) grade the session on behavioural signals — mouse movement,
    scrolling, and dwell time. A freshly-automated page with zero interaction
    scores poorly and is more likely to be challenged or blocked. This injects
    a few realistic mouse moves (with sub-steps), a small scroll down and
    partway back up, and short randomised pauses, so the session looks human
    before we evaluate or screenshot the page.

    Best-effort: any failure (e.g. the page navigated away mid-move) is
    swallowed so it never breaks the scan.

    Args:
        page: The Playwright page to interact with.
    """
    try:
        for _ in range(3):
            x = random.randint(100, _VIEWPORT_WIDTH - 100)
            y = random.randint(100, _VIEWPORT_HEIGHT - 100)
            page.mouse.move(x, y, steps=random.randint(5, 15))
            page.wait_for_timeout(random.randint(80, 220))

        page.mouse.wheel(0, random.randint(300, 600))
        page.wait_for_timeout(random.randint(200, 500))
        page.mouse.wheel(0, -random.randint(100, 300))
        page.wait_for_timeout(random.randint(150, 400))
    except Exception as exc:  # noqa: BLE001 — behaviour sim must never break a scan
        logger.debug("Human-behavior simulation skipped: %s", exc)


def navigate_with_bypass(
    page: Page,
    url: str,
    timeout_ms: int = 15000,
) -> int:
    """Navigate to a URL, automatically bypassing Cloudflare phishing blocks.

    If the page is a Cloudflare "Suspected Phishing" interstitial, waits
    for the Turnstile challenge to auto-solve, then submits the bypass
    form and waits for the real page to load.

    Args:
        page: A Playwright Page to navigate.
        url: The URL to load.
        timeout_ms: Navigation timeout in milliseconds.

    Returns:
        The final HTTP status code (0 if navigation failed entirely).
    """
    try:
        resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        status = resp.status if resp else 0
    except PlaywrightTimeout:
        logger.warning("Navigation timed out for %s", url)
        return 0
    except Exception as exc:
        logger.warning("Navigation failed for %s: %s", url, exc)
        return 0

    # Brief human-like interaction so invisible / score-based challenges see
    # realistic signals before evaluation; also lets the page settle.
    _simulate_human_behavior(page)
    page.wait_for_timeout(800)

    # Check if we landed on a Cloudflare phishing interstitial
    if _is_cloudflare_phishing_block(page):
        logger.info("Cloudflare phishing interstitial detected for %s", url)
        bypassed = _bypass_cloudflare_interstitial(page)
        if bypassed:
            logger.info("Successfully bypassed Cloudflare interstitial for %s", url)
            status = 200
        else:
            logger.warning("Could not bypass Cloudflare interstitial for %s", url)

    # Human-in-the-loop: if an interactive CAPTCHA the tool cannot auto-pass is
    # showing and interactive mode is on, let the operator solve it on-screen.
    if _INTERACTIVE_MODE:
        provider = detect_interactive_captcha(page)
        if provider:
            wait_for_manual_captcha_solve(page, provider)

    return status


def _is_cloudflare_phishing_block(page: Page) -> bool:
    """Check if the current page is a Cloudflare phishing interstitial.

    Args:
        page: The Playwright page to check.

    Returns:
        True if the page is a Cloudflare phishing/malware block.
    """
    try:
        title = page.evaluate("() => document.title.toLowerCase()")
        if "suspected phishing" in title and "cloudflare" in title:
            return True
        if "suspected malware" in title and "cloudflare" in title:
            return True

        body = page.evaluate(
            "() => document.body ? document.body.innerText.toLowerCase()"
            ".substring(0, 1000) : ''"
        )
        if "suspected phishing" in body and "cloudflare" in body:
            return True
    except Exception:
        pass

    return False


def _bypass_cloudflare_interstitial(page: Page) -> bool:
    """Wait for Turnstile to auto-solve and submit the bypass form.

    Args:
        page: A page showing a Cloudflare phishing interstitial.

    Returns:
        True if the bypass succeeded and the real page loaded.
    """
    # Wait for Turnstile token to be populated
    elapsed = 0
    while elapsed < _TURNSTILE_TIMEOUT_MS:
        try:
            has_token = page.evaluate("""() => {
                const inp = document.querySelector(
                    '[name="cf-turnstile-response"]'
                );
                return inp && inp.value && inp.value.length > 10;
            }""")
            if has_token:
                break
        except Exception:
            pass

        page.wait_for_timeout(_TURNSTILE_POLL_MS)
        elapsed += _TURNSTILE_POLL_MS

    if elapsed >= _TURNSTILE_TIMEOUT_MS:
        logger.debug("Turnstile token did not appear within timeout")
        return False

    # Submit the bypass form
    try:
        page.evaluate("() => document.querySelector('form').submit()")
        page.wait_for_timeout(5000)

        # Check that we actually left the interstitial
        if _is_cloudflare_phishing_block(page):
            return False

        return True
    except Exception as exc:
        logger.debug("Form submission failed: %s", exc)
        return False
