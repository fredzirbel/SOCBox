"""Screenshot capture for SOC Box using Playwright.

Captures full-page screenshots with:
- A URL banner overlay showing the final URL after redirects
- Red box annotations around suspicious page elements
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from playwright.sync_api import Page, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeout

from socbox.browser import create_context, launch_browser, navigate_with_bypass

logger = logging.getLogger(__name__)


# CSS selectors and text patterns used to identify suspicious elements
_SUSPICIOUS_SELECTORS = [
    # Password and credential inputs
    'input[type="password"]',
    'input[name*="pass" i]',
    'input[name*="credential" i]',
    'input[name*="login" i]',
    'input[name*="user" i]',
    # Forms that look like login forms
    'form[action*="login" i]',
    'form[action*="signin" i]',
    'form[action*="verify" i]',
    'form[action*="account" i]',
]

# Text content patterns that indicate social engineering
_SUSPICIOUS_TEXT_PATTERNS = [
    "download now",
    "click here to continue",
    "click to continue",
    "verify your account",
    "confirm your identity",
    "update your information",
    "your account has been",
    "suspended",
    "unusual activity",
    "press windows",
    "win+r",
    "windows + r",
    "copy and paste",
    "run this command",
    "powershell",
    "cmd.exe",
    "captcha",
    "verify you are human",
    "click allow",
    "enable notifications",
    "enable content",
]


def capture_screenshot(
    url: str,
    output_dir: Path,
    config: dict[str, Any],
    *,
    browser: Any = None,
) -> Path | None:
    """Capture an annotated full-page screenshot of the URL.

    Navigates to the URL with headless Chromium, injects a URL banner
    showing the final landing URL, highlights suspicious elements with
    red outlines, then takes a full-page screenshot.

    Args:
        url: The URL to screenshot.
        output_dir: Directory to save the screenshot PNG.
        config: The loaded SOC Box configuration dictionary.
        browser: Optional shared Playwright Browser instance. When provided,
            a new context is created from it instead of launching a new browser.

    Returns:
        Path to the saved screenshot, or None if capture failed.
    """
    timeout_ms = config.get("requests", {}).get("timeout", 10) * 1000
    nav_timeout_ms = max(timeout_ms * 3, 15000)

    parsed = urlparse(url)
    domain = (parsed.hostname or "unknown").replace(".", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}.png"
    output_path = output_dir / filename

    own_browser = browser is None

    try:
        if own_browser:
            pw_ctx = sync_playwright().start()
            browser = launch_browser(pw_ctx, url)

        context = create_context(browser)
        page = context.new_page()

        status = navigate_with_bypass(page, url, timeout_ms=nav_timeout_ms)
        if status == 0:
            context.close()
            if own_browser:
                browser.close()
                pw_ctx.stop()
            logger.warning("Screenshot navigation failed for %s", url)
            return None

        # Get the final URL after any redirects
        final_url = page.url

        # Inject URL banner overlay
        _inject_url_banner(page, final_url, url)

        # Annotate suspicious elements
        annotation_count = _annotate_suspicious_elements(page)
        logger.debug("Annotated %d suspicious elements on %s", annotation_count, url)

        page.screenshot(path=str(output_path), full_page=True)
        context.close()
        if own_browser:
            browser.close()
            pw_ctx.stop()

        logger.info("Screenshot saved: %s", output_path)
        return output_path

    except PlaywrightTimeout:
        logger.warning("Screenshot timed out for %s", url)
        return None
    except Exception as exc:
        logger.error("Screenshot failed for %s: %s", url, exc)
        return None


def _inject_url_banner(page: Page, final_url: str, original_url: str) -> None:
    """Inject a URL bar banner at the top of the page.

    Shows the final URL after redirects. If the URL changed from the
    original, both are displayed.

    Args:
        page: The Playwright page object.
        final_url: The URL the page actually landed on.
        original_url: The URL that was originally requested.
    """
    # Escape quotes for safe JS injection
    final_escaped = final_url.replace("\\", "\\\\").replace("'", "\\'")
    original_escaped = original_url.replace("\\", "\\\\").replace("'", "\\'")

    # Treat trivial redirects (http→https upgrade, bare↔www) as non-redirects
    from socbox.analyzers.http_response import _is_trivial_redirect

    redirected = final_url.rstrip("/") != original_url.rstrip("/")
    if redirected and _is_trivial_redirect(original_url, final_url):
        redirected = False

    redirect_line = ""
    if redirected:
        redirect_line = (
            f"<div style='font-size:13px;color:#ff6b6b;margin-top:2px;'>"
            f"Redirected from: {original_escaped}</div>"
        )

    page.evaluate(f"""() => {{
        const banner = document.createElement('div');
        banner.id = 'socbox-url-banner';
        banner.innerHTML = `
            <div style="
                position: relative;
                top: 0;
                left: 0;
                width: 100%;
                background: #2d2d2d;
                color: #e0e0e0;
                font-family: 'Segoe UI', Consolas, monospace;
                font-size: 16px;
                padding: 8px 16px;
                box-sizing: border-box;
                z-index: 999999;
                border-bottom: 2px solid #444;
                display: flex;
                flex-direction: column;
            ">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="
                        background: #c0392b;
                        color: white;
                        font-size: 10px;
                        font-weight: bold;
                        padding: 2px 6px;
                        border-radius: 3px;
                    ">SOC Box</span>
                    <span style="
                        background: #3d3d3d;
                        padding: 4px 12px;
                        border-radius: 4px;
                        flex: 1;
                        overflow: hidden;
                        text-overflow: ellipsis;
                        white-space: nowrap;
                    ">{final_escaped}</span>
                </div>
                {redirect_line}
            </div>
        `;
        document.body.insertBefore(banner, document.body.firstChild);
    }}""")


def _annotate_suspicious_elements(page: object) -> int:
    """Find and highlight suspicious elements on the page.

    Draws red outlines around elements matching suspicious CSS selectors
    or containing suspicious text patterns. Adds a small label above
    each highlighted element.

    Args:
        page: The Playwright page object.

    Returns:
        Number of elements annotated.
    """
    selectors_json = json.dumps(_SUSPICIOUS_SELECTORS)
    patterns_json = json.dumps(_SUSPICIOUS_TEXT_PATTERNS)

    count = page.evaluate(f"""() => {{
        const selectors = {selectors_json};
        const textPatterns = {patterns_json};
        let annotationCount = 0;

        function annotateElement(el, reason) {{
            // Skip if already annotated or not visible
            if (el.dataset.socboxAnnotated) return false;
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return false;

            el.dataset.socboxAnnotated = 'true';
            el.style.outline = '3px solid #e74c3c';
            el.style.outlineOffset = '2px';
            el.style.position = el.style.position || 'relative';

            // Add label
            const label = document.createElement('div');
            label.textContent = reason;
            label.style.cssText = `
                position: absolute;
                top: -22px;
                left: 0;
                background: #e74c3c;
                color: white;
                font-size: 10px;
                font-weight: bold;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: Arial, sans-serif;
                z-index: 999998;
                white-space: nowrap;
                pointer-events: none;
            `;

            // Make parent relative if needed for label positioning
            const parent = el.parentElement;
            if (parent) {{
                const parentPos = window.getComputedStyle(parent).position;
                if (parentPos === 'static') {{
                    parent.style.position = 'relative';
                }}
            }}

            el.style.position = 'relative';
            el.appendChild(label);
            annotationCount++;
            return true;
        }}

        // Check CSS selectors
        for (const selector of selectors) {{
            try {{
                const elements = document.querySelectorAll(selector);
                elements.forEach(el => {{
                    let reason = 'SUSPICIOUS INPUT';
                    if (el.type === 'password' ||
                        (el.name && el.name.toLowerCase().includes('pass'))) {{
                        reason = 'PASSWORD FIELD';
                    }} else if (el.tagName === 'FORM') {{
                        reason = 'SUSPICIOUS FORM';
                    }}
                    annotateElement(el, reason);
                }});
            }} catch(e) {{}}
        }}

        // Check text content patterns
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_ELEMENT,
            null
        );

        const clickableElements = [];
        while (walker.nextNode()) {{
            const node = walker.currentNode;
            const tag = node.tagName.toLowerCase();
            // Only check interactive/visible elements and headings
            const interactiveTags = ['a', 'button', 'div', 'span',
                'p', 'h1', 'h2', 'h3', 'h4', 'li', 'label'];
            if (interactiveTags.includes(tag)) {{
                clickableElements.push(node);
            }}
        }}

        for (const el of clickableElements) {{
            // Get direct text content (not children's text)
            const text = el.textContent.toLowerCase().trim();
            if (!text || text.length > 500) continue;

            for (const pattern of textPatterns) {{
                if (text.includes(pattern)) {{
                    let reason = 'SUSPICIOUS TEXT';
                    if (pattern.includes('download')) reason = 'DOWNLOAD BUTTON';
                    else if (pattern.includes('captcha') ||
                        pattern.includes('human'))
                        reason = 'CAPTCHA/VERIFICATION';
                    else if (pattern.includes('win+r') ||
                        pattern.includes('windows + r') ||
                        pattern.includes('powershell') ||
                        pattern.includes('cmd.exe') ||
                        pattern.includes('run this command') ||
                        pattern.includes('copy and paste'))
                        reason = 'CLICKFIX ATTACK';
                    else if (pattern.includes('allow') ||
                        pattern.includes('notification') ||
                        pattern.includes('enable'))
                        reason = 'PERMISSION PROMPT';
                    else if (pattern.includes('verify') ||
                        pattern.includes('confirm') ||
                        pattern.includes('update') ||
                        pattern.includes('suspended') ||
                        pattern.includes('unusual'))
                        reason = 'SOCIAL ENGINEERING';
                    else if (pattern.includes('click')) reason = 'SUSPICIOUS BUTTON';
                    annotateElement(el, reason);
                    break;
                }}
            }}
        }}

        return annotationCount;
    }}""")

    return count or 0


# ---------------------------------------------------------------------------
# CTA button detection patterns
# ---------------------------------------------------------------------------

# Text patterns (case-insensitive) that identify call-to-action buttons
_CTA_TEXT_PATTERNS = [
    "download",
    "click here",
    "continue",
    "open",
    "view",
    "get started",
    "start",
    "confirm",
    "verify",
    "allow",
    "accept",
    "enable",
    "submit",
    "go",
    "proceed",
    "view pdf",
    "view document",
    "your pdf is ready",
    "click to download",
]

# CSS selectors that identify clickable CTA-like elements
_CTA_SELECTORS = [
    "button",
    "a.btn",
    "a.button",
    '[role="button"]',
    'input[type="submit"]',
]


def capture_multi_screenshots(
    url: str,
    output_dir: Path,
    config: dict[str, Any],
    *,
    browser: Any = None,
) -> dict[str, str | None]:
    """Capture initial page screenshot and post-CTA-click screenshot.

    Opens the URL, takes an initial screenshot of the landing page, then
    searches for the first obvious CTA button (download, continue, etc.).
    If a CTA is found it is clicked, a short wait allows the page to
    react, and a second screenshot is captured.

    Args:
        url: The URL to screenshot.
        output_dir: Directory to save the screenshot PNGs.
        config: The loaded SOC Box configuration dictionary.
        browser: Optional shared Playwright Browser instance. When provided,
            a new context is created from it instead of launching a new browser.

    Returns:
        Dict with keys:
        - 'initial': filename of initial screenshot (or None)
        - 'initial_url': the URL shown on initial load
        - 'cta': filename of post-CTA screenshot (or None if no CTA found/clicked)
        - 'cta_url': the URL after clicking the CTA (or None)
        - 'cta_text': text of the CTA button that was clicked (or None)
    """
    result: dict[str, str | None] = {
        "initial": None,
        "initial_url": None,
        "cta": None,
        "cta_url": None,
        "cta_text": None,
    }

    timeout_ms = config.get("requests", {}).get("timeout", 10) * 1000
    nav_timeout_ms = max(timeout_ms * 3, 15000)

    parsed = urlparse(url)
    domain = (parsed.hostname or "unknown").replace(".", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    own_browser = browser is None
    pw_ctx = None

    try:
        if own_browser:
            pw_ctx = sync_playwright().start()
            browser = launch_browser(pw_ctx, url)

        context = create_context(browser)
        page = context.new_page()

        # Navigate to the URL
        status = navigate_with_bypass(page, url, timeout_ms=nav_timeout_ms)
        if status == 0:
            context.close()
            if own_browser:
                browser.close()
                pw_ctx.stop()
            logger.warning("Multi-screenshot navigation failed for %s", url)
            return result

        # ---- Screenshot #1: Initial page load ----
        initial_url = page.url
        result["initial_url"] = initial_url

        _inject_url_banner(page, initial_url, url)
        _annotate_suspicious_elements(page)

        initial_filename = f"{domain}_{timestamp}_initial.png"
        initial_path = output_dir / initial_filename
        page.screenshot(path=str(initial_path), full_page=True)
        result["initial"] = initial_filename
        logger.info("Multi-screenshot initial saved: %s", initial_path)

        # ---- Find and click the first CTA button ----
        cta_patterns_json = json.dumps(_CTA_TEXT_PATTERNS)
        cta_selectors_json = json.dumps(_CTA_SELECTORS)

        cta_candidates = page.evaluate(f"""() => {{
            const textPatterns = {cta_patterns_json};
            const selectors = {cta_selectors_json};
            const results = [];
            const seen = new Set();

            // Helper: check if an element's text matches a CTA pattern
            function matchesCTA(el) {{
                const text = (el.textContent || el.value || '').trim();
                // Skip elements with too-short or too-long text
                if (text.length < 3 || text.length > 50) return null;
                const lower = text.toLowerCase();
                for (const pattern of textPatterns) {{
                    if (lower.includes(pattern)) {{
                        return text;
                    }}
                }}
                return null;
            }}

            // Check elements matching CTA selectors
            for (const selector of selectors) {{
                try {{
                    const elements = document.querySelectorAll(selector);
                    for (const el of elements) {{
                        // Skip hidden or zero-size elements
                        const rect = el.getBoundingClientRect();
                        if (rect.width === 0 || rect.height === 0) continue;
                        if (el.offsetParent === null && el.style.position !== 'fixed') continue;

                        const matchedText = matchesCTA(el);
                        if (matchedText && !seen.has(el)) {{
                            seen.add(el);
                            // Build a unique selector path for this element
                            let path = el.tagName.toLowerCase();
                            if (el.id) path += '#' + el.id;
                            else if (el.className && typeof el.className === 'string')
                                path += '.' + el.className.split(/\\s+/).filter(Boolean).join('.');
                            results.push({{
                                text: matchedText,
                                selector: path,
                                index: results.length
                            }});
                        }}
                    }}
                }} catch(e) {{}}
            }}

            // Also walk all interactive-looking elements for CTA text
            const walker = document.createTreeWalker(
                document.body,
                NodeFilter.SHOW_ELEMENT,
                null
            );
            while (walker.nextNode()) {{
                const node = walker.currentNode;
                const tag = node.tagName.toLowerCase();
                if (!['a', 'button', 'div', 'span', 'input'].includes(tag)) continue;
                if (seen.has(node)) continue;

                const rect = node.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) continue;

                const matchedText = matchesCTA(node);
                if (matchedText) {{
                    seen.add(node);
                    let path = tag;
                    if (node.id) path += '#' + node.id;
                    else if (node.className && typeof node.className === 'string')
                        path += '.' + node.className.split(/\\s+/).filter(Boolean).join('.');
                    results.push({{
                        text: matchedText,
                        selector: path,
                        index: results.length
                    }});
                }}
            }}

            return results;
        }}""")

        if cta_candidates:
            cta = cta_candidates[0]
            cta_text = cta["text"]
            logger.info(
                "Multi-screenshot found CTA button: %r on %s", cta_text, url,
            )

            # Click the first CTA candidate using its text content
            try:
                # Use Playwright's text-based locator for reliable clicking
                clicked = page.evaluate(f"""() => {{
                    const textPatterns = {cta_patterns_json};
                    const selectors = {cta_selectors_json};
                    const seen = new Set();

                    function matchesCTA(el) {{
                        const text = (el.textContent || el.value || '').trim();
                        if (text.length < 3 || text.length > 50) return null;
                        const lower = text.toLowerCase();
                        for (const pattern of textPatterns) {{
                            if (lower.includes(pattern)) return text;
                        }}
                        return null;
                    }}

                    // First check selector-matched elements
                    for (const selector of selectors) {{
                        try {{
                            const elements = document.querySelectorAll(selector);
                            for (const el of elements) {{
                                const rect = el.getBoundingClientRect();
                                if (rect.width === 0 || rect.height === 0) continue;
                                if (el.offsetParent === null &&
                                    el.style.position !== 'fixed') continue;
                                if (matchesCTA(el)) {{
                                    el.click();
                                    return true;
                                }}
                            }}
                        }} catch(e) {{}}
                    }}

                    // Walk all interactive elements
                    const walker = document.createTreeWalker(
                        document.body, NodeFilter.SHOW_ELEMENT, null
                    );
                    while (walker.nextNode()) {{
                        const node = walker.currentNode;
                        const tag = node.tagName.toLowerCase();
                        if (!['a', 'button', 'div', 'span', 'input'].includes(tag)) continue;
                        const rect = node.getBoundingClientRect();
                        if (rect.width === 0 || rect.height === 0) continue;
                        if (matchesCTA(node)) {{
                            node.click();
                            return true;
                        }}
                    }}

                    return false;
                }}""")

                if clicked:
                    result["cta_text"] = cta_text

                    # Wait for navigation or content change
                    try:
                        page.wait_for_load_state("networkidle", timeout=3000)
                    except PlaywrightTimeout:
                        pass
                    # Additional fixed wait for dynamic content
                    page.wait_for_timeout(3000)

                    # ---- Screenshot #2: After CTA click ----
                    cta_url = page.url
                    result["cta_url"] = cta_url

                    # Remove old banner before injecting the new one
                    page.evaluate("""() => {
                        const old = document.getElementById('socbox-url-banner');
                        if (old) old.remove();
                    }""")

                    _inject_url_banner(page, cta_url, url)
                    _annotate_suspicious_elements(page)

                    cta_filename = f"{domain}_{timestamp}_cta.png"
                    cta_path = output_dir / cta_filename
                    page.screenshot(path=str(cta_path), full_page=True)
                    result["cta"] = cta_filename
                    logger.info("Multi-screenshot CTA saved: %s", cta_path)
                else:
                    logger.debug("CTA click returned false for %s", url)

            except Exception as click_exc:
                logger.warning(
                    "Failed to click CTA on %s: %s", url, click_exc,
                )
        else:
            logger.debug("No CTA buttons found on %s", url)

        context.close()
        if own_browser:
            browser.close()
            pw_ctx.stop()

        return result

    except PlaywrightTimeout:
        logger.warning("Multi-screenshot timed out for %s", url)
        return result
    except Exception as exc:
        logger.error("Multi-screenshot failed for %s: %s", url, exc)
        return result
