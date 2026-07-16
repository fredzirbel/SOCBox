"""Shared Playwright browser utilities for SOC Box.

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

import concurrent.futures
import json
import logging
import random
import sys
import threading

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    sync_playwright,
)
from playwright.sync_api import (
    TimeoutError as PlaywrightTimeout,
)

from socbox.dns_util import build_chromium_args

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
# hCaptcha checkbox or image challenge, interactive Turnstile) pauses the scan
# so the operator can solve it in the on-screen browser window; analysis
# resumes when the operator presses Enter (or, with no terminal, when a solved
# response token is detected).
#
# Control state is **thread-local**, set per scan. Each scan runs its browser
# work on a single thread (the scanner drives browser analyzers + screenshots
# sequentially on the scan thread), so per-thread keying keeps concurrent scans
# isolated: an interactive / human-present scan never makes a sibling headless
# scan pause, and the action-notifier no longer races across concurrent web
# scans. Two solve modes exist:
#   - interactive: CLI, headed on-screen, operator solves locally (Enter/token).
#   - human_present: web UI, transparent noVNC takeover (see remote_takeover_solve).
_scan_tls = threading.local()

# How long to wait (no-terminal fallback) for a solved token before giving up.
_CAPTCHA_SOLVE_TIMEOUT_MS = 180_000  # 3 minutes
_CAPTCHA_POLL_MS = 1000


def set_interactive_mode(enabled: bool) -> None:
    """Enable CLI human-in-the-loop solving (headed, on-screen) for this thread."""
    _scan_tls.interactive = enabled


def set_human_present(enabled: bool) -> None:
    """Mark whether an analyst is watching this scan and can solve a CAPTCHA live.

    True only for single, analyst-initiated web-UI scans (transparent noVNC
    takeover). False for bulk, agent/TAP, and async scans, which must never
    block on a human.
    """
    _scan_tls.human_present = enabled


def set_action_notifier(notifier) -> None:
    """Register (or clear with None) the per-scan analyst-action notifier.

    The notifier fires when a scan hits a CAPTCHA gate; the web layer turns it
    into an ``action_required`` SSE event (and enriches it with the noVNC
    ``view_url``). Signature: ``notifier(info: dict) -> None``.
    """
    _scan_tls.action_notifier = notifier


def set_solve_timeout_ms(ms: int) -> None:
    """Set the per-scan manual-solve timeout in milliseconds (thread-local)."""
    _scan_tls.solve_timeout_ms = ms


def _interactive_mode() -> bool:
    return getattr(_scan_tls, "interactive", False)


def _human_present() -> bool:
    return getattr(_scan_tls, "human_present", False)


def _get_action_notifier():
    return getattr(_scan_tls, "action_notifier", None)


def _solve_timeout_ms() -> int:
    return getattr(_scan_tls, "solve_timeout_ms", _CAPTCHA_SOLVE_TIMEOUT_MS)


def is_human_present() -> bool:
    """Public: True if an analyst is watching this scan and can solve a CAPTCHA live."""
    return _human_present()


def get_solved_state() -> dict | None:
    """Return the clearance state captured after a CAPTCHA solve this scan, if any.

    Analyzers that build their own browser context (e.g. the download fallback)
    can replay this so a gate solved earlier in the scan stays unlocked.
    """
    return getattr(_ctx_tls, "solved_state", None)

# Visible-iframe src signatures for CAPTCHA widgets. Includes the always-present
# anchor/checkbox frame (so a plain "I'm not a robot" gate pauses too), not just
# the image-challenge popup. A size filter in detect_interactive_captcha() skips
# hidden 0-size frames so we only fire on a rendered widget.
_CAPTCHA_SIGNATURES = {
    "reCAPTCHA": [
        "recaptcha/api2/anchor", "recaptcha/api2/bframe",
        "recaptcha/enterprise/anchor", "recaptcha/enterprise/bframe",
    ],
    "hCaptcha": ["hcaptcha.com", "newassets.hcaptcha.com"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com"],
}

# Names of the hidden field each provider populates once a challenge is solved.
_CAPTCHA_TOKEN_FIELDS = [
    "g-recaptcha-response",
    "h-captcha-response",
    "cf-turnstile-response",
]

# Thread-local storage_state (cookies/origins) captured after the operator
# solves a CAPTCHA. A scan navigates the same URL several times, each in a
# fresh isolated context; replaying this state into later contexts carries the
# clearance cookie forward so the operator solves the challenge only once
# instead of being re-prompted per navigation. Only used in interactive mode.
_ctx_tls = threading.local()


def reset_solved_state() -> None:
    """Clear any captured post-solve storage state (call at scan start)."""
    _ctx_tls.solved_state = None


def _stash_solved_state(page: Page) -> None:
    """Capture cookies/storage after a solve so later contexts reuse them."""
    try:
        _ctx_tls.solved_state = page.context.storage_state()
        logger.debug("Captured post-solve storage state for reuse this scan")
    except Exception as exc:
        logger.debug("Could not capture post-solve storage state: %s", exc)


def detect_interactive_captcha(page: Page) -> str:
    """Return the provider name of a *rendered* CAPTCHA widget, or ``""``.

    Matches any iframe whose src belongs to a known provider (checkbox/anchor
    or image-challenge frame) and that is actually rendered. Hidden frames -
    e.g. the reCAPTCHA image-challenge frame before it is shown - report a
    zero-size bounding box and are skipped, so this fires on a visible gate
    rather than on dormant markup.

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
                // Skip hidden / collapsed frames; keep the ~300x78 checkbox
                // and the larger image-challenge popup.
                if (rect.width < 50 || rect.height < 20) continue;
                for (const name in sigs) {{
                    if (sigs[name].some(p => src.includes(p))) return name;
                }}
            }}
            return '';
        }}""") or ""
    except Exception as exc:
        logger.debug("Interactive CAPTCHA detection failed: %s", exc)
        return ""


def _captcha_token_present(page: Page) -> bool:
    """Return True if a solved-CAPTCHA response token has been populated.

    Used as the no-terminal resume signal: a populated ``g-recaptcha-response``
    / ``h-captcha-response`` / ``cf-turnstile-response`` field means the
    challenge was solved, even though the widget itself stays on the page.
    """
    fields_json = json.dumps(_CAPTCHA_TOKEN_FIELDS)
    try:
        return bool(page.evaluate(f"""() => {{
            const names = {fields_json};
            for (const n of names) {{
                const el = document.querySelector(
                    `textarea[name="${{n}}"], input[name="${{n}}"]`
                );
                if (el && el.value && el.value.length > 20) return true;
            }}
            return false;
        }}"""))
    except Exception as exc:
        logger.debug("CAPTCHA token check failed: %s", exc)
        return False


def _poll_for_solve(page: Page, timeout_ms: int) -> bool:
    """Poll for a solved-CAPTCHA response token until *timeout_ms* elapses.

    The terminal-free resume signal shared by the CLI no-TTY path and the web
    noVNC takeover: a populated response-token field means the challenge was
    solved (the widget itself stays on the page). Does not stash state.

    Args:
        page: The Playwright page showing the challenge.
        timeout_ms: How long to wait before giving up.

    Returns:
        True if a solved token appeared, False on timeout.
    """
    elapsed = 0
    while elapsed < timeout_ms:
        if _captcha_token_present(page):
            return True
        page.wait_for_timeout(_CAPTCHA_POLL_MS)
        elapsed += _CAPTCHA_POLL_MS
    return False


def wait_for_manual_captcha_solve(page: Page, provider: str) -> bool:
    """Pause the scan while the operator solves a CAPTCHA in the browser window.

    CLI path. With an interactive terminal, blocks until the operator presses
    Enter - reliable across every CAPTCHA type (the checkbox widget stays on the
    page after solving, so waiting for it to "disappear" does not work). Without
    a terminal, falls back to polling for a solved response token. The web UI
    uses ``remote_takeover_solve`` instead, never this function's TTY branch.

    Args:
        page: The Playwright page showing the challenge.
        provider: Provider name for operator-facing messaging.

    Returns:
        True if the operator confirmed / a solved token appeared, False on
        timeout in the no-terminal fallback.
    """
    logger.warning("Interactive %s CAPTCHA detected - pausing for manual solve", provider)
    print(
        f"\n[SOC Box] {provider} CAPTCHA detected in the browser window.",
        flush=True,
    )

    if sys.stdin is not None and sys.stdin.isatty():
        try:
            input("[SOC Box] Solve it in the window, then press Enter here to continue… ")
            logger.info("Operator confirmed CAPTCHA solve - resuming")
            _stash_solved_state(page)
            print("[SOC Box] Resuming analysis.\n", flush=True)
            return True
        except EOFError:
            pass  # No usable stdin after all - fall through to token polling.

    timeout_s = _CAPTCHA_SOLVE_TIMEOUT_MS // 1000
    print(
        f"[SOC Box] No interactive terminal; waiting up to {timeout_s}s for a "
        f"solved token…",
        flush=True,
    )
    if _poll_for_solve(page, _CAPTCHA_SOLVE_TIMEOUT_MS):
        logger.info("Solved CAPTCHA token detected - resuming")
        _stash_solved_state(page)
        print("[SOC Box] CAPTCHA solved - resuming analysis.\n", flush=True)
        return True

    logger.warning("CAPTCHA not solved within %ds - continuing", timeout_s)
    print("[SOC Box] Timed out waiting for CAPTCHA - continuing analysis.\n", flush=True)
    return False


# ---------------------------------------------------------------------------
# Transparent web takeover (noVNC)
# ---------------------------------------------------------------------------
# When a single analyst-initiated web scan (human_present) hits an
# un-automatable CAPTCHA, the headless scan hands the gate off to a headed
# browser on the shared X display (visible via noVNC) so the analyst can solve
# it in their tab. The headed solve runs on a dedicated single worker thread:
# Playwright's sync API is thread-bound, so creating/driving the headed browser
# on one thread is required, and a single worker also serializes takeovers on
# the one shared display. The headless scan thread blocks on the result (it is
# waiting for a human anyway), then replays the captured clearance.
_takeover_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="socbox-takeover",
)


def _takeover_job(
    url: str, provider: str, session_state: dict | None, timeout_ms: int,
) -> dict | None:
    """Run a headed solve on the shared display; return clearance state or None.

    Runs on the dedicated takeover thread. Launches a headed browser on the X
    display, replays the scan's session so the gate matches, waits for the
    analyst to solve, and returns the post-solve ``storage_state``.
    """
    pw = None
    browser = None
    try:
        pw = sync_playwright().start()
        browser = launch_browser(pw, url, interactive=True)

        kwargs: dict = {
            # Let the page fill the maximized window so the analyst sees a large
            # browser in the noVNC viewer (rather than a small fixed viewport).
            "no_viewport": True,
            "ignore_https_errors": True,
            "user_agent": USER_AGENT,
            "locale": "en-US",
            "timezone_id": "America/New_York",
        }
        if session_state:
            kwargs["storage_state"] = session_state

        context = browser.new_context(**kwargs)
        context.add_init_script(_INIT_SCRIPT)
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception as exc:
            logger.warning("Takeover navigation failed for %s: %s", url, exc)
            return None

        logger.info("Takeover: awaiting analyst solve of %s on %s", provider, url)
        if not _poll_for_solve(page, timeout_ms):
            logger.warning("Takeover solve timed out for %s", url)
            return None

        try:
            return context.storage_state()
        except Exception as exc:
            logger.debug("Takeover storage_state capture failed: %s", exc)
            return None
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass


def remote_takeover_solve(
    page: Page, url: str, provider: str, timeout_ms: int,
) -> bool:
    """Hand a CAPTCHA off to a headed noVNC session for an analyst to solve.

    Called from the headless scan thread when an analyst is present. Captures
    the scan's current session, runs the headed solve on the dedicated takeover
    thread (serialized on the shared display), and on success stashes the
    clearance for this scan to replay across its later navigations.

    Args:
        page: The headless scan page that hit the gate.
        url: The gated URL.
        provider: Detected CAPTCHA provider (for logging).
        timeout_ms: How long to wait for the analyst.

    Returns:
        True if the analyst solved the challenge.
    """
    session_state = None
    try:
        session_state = page.context.storage_state()
    except Exception as exc:
        logger.debug("Could not capture scan session for takeover: %s", exc)

    future = _takeover_executor.submit(
        _takeover_job, url, provider, session_state, timeout_ms,
    )
    try:
        solved_state = future.result(timeout=(timeout_ms / 1000) + 60)
    except Exception as exc:
        logger.warning("Takeover solve failed for %s: %s", url, exc)
        return False

    if solved_state:
        _ctx_tls.solved_state = solved_state
        logger.info("Takeover solved - clearance captured for %s", url)
        return True
    return False


def _replay_clearance_and_reload(page: Page, url: str) -> None:
    """Inject the just-solved clearance into the live page and reload past the gate."""
    state = getattr(_ctx_tls, "solved_state", None)
    if not state:
        return
    try:
        cookies = state.get("cookies", []) if isinstance(state, dict) else []
        if cookies:
            page.context.add_cookies(cookies)
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
    except Exception as exc:
        logger.debug("Clearance replay/reload failed for %s: %s", url, exc)


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

    if interactive:
        # Fill the virtual display so the live noVNC viewer shows a large,
        # easy-to-read browser. The container has no window manager, so set the
        # geometry explicitly rather than relying on --start-maximized alone.
        base_args.extend([
            "--window-position=0,0",
            "--window-size=1920,1080",
            "--start-maximized",
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

    If a CAPTCHA was already solved earlier in this scan - whether by the CLI
    operator or via the web noVNC takeover - the captured clearance cookies are
    replayed into the new context so the same challenge is not presented again
    on later navigations.

    Args:
        browser: A launched Browser instance.

    Returns:
        A configured BrowserContext.
    """
    kwargs: dict = {
        "viewport": {"width": _VIEWPORT_WIDTH, "height": _VIEWPORT_HEIGHT},
        "ignore_https_errors": True,
        "user_agent": USER_AGENT,
        "locale": "en-US",
        "timezone_id": "America/New_York",
    }

    solved_state = getattr(_ctx_tls, "solved_state", None)
    if solved_state is not None:
        kwargs["storage_state"] = solved_state

    context = browser.new_context(**kwargs)
    context.add_init_script(_INIT_SCRIPT)
    return context


def _simulate_human_behavior(page: Page) -> None:
    """Perform brief, bounded human-like interaction on the current page.

    Invisible / score-based challenges (reCAPTCHA v3, Cloudflare Turnstile in
    managed mode) grade the session on behavioural signals - mouse movement,
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
    except Exception as exc:  # noqa: BLE001 - behaviour sim must never break a scan
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

    # Detect an interactive CAPTCHA gate (for analyst notification and/or solve).
    provider = ""
    notifier = _get_action_notifier()
    if _interactive_mode() or _human_present() or notifier is not None:
        provider = detect_interactive_captcha(page)

    # Signal that a human is needed: the web layer turns this into an
    # action_required SSE event (desktop notification + noVNC view_url).
    if provider and notifier is not None:
        try:
            notifier({"kind": "captcha", "provider": provider, "url": url})
        except Exception as exc:
            logger.debug("Action notifier failed: %s", exc)

    # Resolve the gate. CLI: pause for an on-screen solve. Web (human present):
    # hand off to a headed noVNC session, then replay clearance past the gate.
    # Bulk / agent / async scans (no interactive, no human) just notified above.
    if provider and _interactive_mode():
        wait_for_manual_captcha_solve(page, provider)
    elif provider and _human_present():
        if remote_takeover_solve(page, url, provider, _solve_timeout_ms()):
            _replay_clearance_and_reload(page, url)

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
