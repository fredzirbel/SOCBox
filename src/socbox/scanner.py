"""Scanner orchestrator for SOC Box."""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from playwright.sync_api import Browser, Playwright, sync_playwright

from socbox.analyzers import ALL_ANALYZERS
from socbox.browser import (
    launch_browser,
    reset_solved_state,
    set_action_notifier,
    set_human_present,
    set_interactive_mode,
    set_solve_timeout_ms,
)
from socbox.classification import classify
from socbox.dns_util import compute_host_resolver_rule
from socbox.models import (
    AnalyzerResult,
    AnalyzerStatus,
    RiskCategory,
    ScanReport,
)
from socbox.scoring import calculate_score, score_breakdown
from socbox.screenshot import capture_multi_screenshots, capture_screenshot

logger = logging.getLogger(__name__)

# Type alias for the optional streaming callback.
# Signature: on_event(event_type: str, data: dict) -> None
EventCallback = Callable[[str, dict], None] | None

# Analyzers that need a Playwright browser - must run on the Playwright thread.
_BROWSER_ANALYZERS = {
    "Page Content Analysis",
    "Link Discovery Analysis",
}

# Analyzers that start in the thread pool (requests-based) but need a
# browser fallback when requests is blocked (Cloudflare, bot-gating, etc.).
# These run on the main Playwright thread AFTER all browser analyzers finish,
# so they don't block the concurrent thread pool but still get the browser.
_DEFERRED_BROWSER_ANALYZERS = {
    "Download Analysis",
}

# Config key mapping for analyzer weights.
_ANALYZER_WEIGHT_KEYS = {
    "URL Lexical Analysis": "url_lexical",
    "WHOIS/DNS Inspection": "whois_dns",
    "SSL/TLS Certificate": "ssl_tls",
    "HTTP Response Analysis": "http_response",
    "Page Content Analysis": "page_content",
    "Link Discovery Analysis": "link_discovery",
    "Download Analysis": "download",
    "Threat Feed Integration": "threat_feeds",
}

# ---------------------------------------------------------------------------
# Thread-local browser pool
# ---------------------------------------------------------------------------
# Each scan executor thread gets its own Playwright + Browser instance.
# Playwright's sync API is greenlet-bound to a single thread, so sharing
# a browser across threads causes segfaults.  Thread-local storage ensures
# each worker has an independent, persistent browser.

_tls = threading.local()
_all_browsers_lock = threading.Lock()
_all_browsers: list[tuple[Playwright, Browser]] = []


def _get_browser(url: str, interactive: bool = False) -> tuple[Playwright, Browser]:
    """Return the thread-local Playwright + Browser, creating them if needed.

    Each worker thread in the scan executor pool maintains its own
    persistent browser.  If the cached browser has crashed, it is
    automatically restarted.

    Args:
        url: The URL to scan (used for initial DNS resolution on launch).
        interactive: When True, launch the browser on-screen so an operator
            can solve CAPTCHAs manually (human-in-the-loop mode).

    Returns:
        Tuple of (Playwright, Browser).
    """
    pw = getattr(_tls, "pw", None)
    browser = getattr(_tls, "browser", None)

    # Chromium bakes --host-resolver-rules (and on-screen vs off-screen window
    # placement) in at launch and cannot change either afterwards. A browser
    # cached for an earlier URL therefore carries that URL's DNS override (or
    # none), which makes it unable to reach a new domain that needs a different
    # DoH-resolved MAP rule - exactly the phishing domains this tool exists to
    # analyse. Relaunch when the required rule, or the interactive mode, differs
    # from what the cached browser was launched with.
    required_rule = compute_host_resolver_rule(url)

    if pw is not None and browser is not None:
        cached_rule = getattr(_tls, "resolver_rule", "")
        cached_interactive = getattr(_tls, "interactive", False)
        if cached_rule != required_rule or cached_interactive != interactive:
            logger.info(
                "Browser launch params changed (rule %r->%r, interactive "
                "%s->%s); relaunching browser",
                cached_rule, required_rule, cached_interactive, interactive,
            )
            _close_thread_browser()
            pw = browser = None
        else:
            try:
                # Health check - access a property to see if the browser is alive
                _ = browser.contexts
                return pw, browser
            except Exception:
                logger.warning("Thread-local browser is dead, restarting…")
                _close_thread_browser()
                pw = browser = None

    pw = sync_playwright().start()
    browser = launch_browser(pw, url, interactive=interactive)
    _tls.pw = pw
    _tls.browser = browser
    _tls.resolver_rule = required_rule
    _tls.interactive = interactive

    with _all_browsers_lock:
        _all_browsers.append((pw, browser))

    return pw, browser


def _close_thread_browser() -> None:
    """Close the thread-local browser and stop Playwright.

    Safe to call even if nothing is cached on this thread.
    """
    browser = getattr(_tls, "browser", None)
    pw = getattr(_tls, "pw", None)

    if browser is not None:
        try:
            browser.close()
        except Exception:
            pass
        _tls.browser = None

    if pw is not None:
        try:
            pw.stop()
        except Exception:
            pass
        _tls.pw = None

    _tls.resolver_rule = ""
    _tls.interactive = False


def shutdown_browser() -> None:
    """Close all browsers across all worker threads on app shutdown."""
    with _all_browsers_lock:
        for pw, browser in _all_browsers:
            try:
                browser.close()
            except Exception:
                pass
            try:
                pw.stop()
            except Exception:
                pass
        _all_browsers.clear()


# ---------------------------------------------------------------------------
# Event helpers (for SSE streaming)
# ---------------------------------------------------------------------------

def _emit(on_event: EventCallback, event_type: str, data: dict) -> None:
    """Safely invoke the optional streaming callback.

    Args:
        on_event: The callback, or None.
        event_type: The SSE event name (e.g. "analyzer", "score").
        data: JSON-serialisable payload.
    """
    if on_event is not None:
        try:
            on_event(event_type, data)
        except Exception as exc:
            logger.debug("Event callback failed for %s: %s", event_type, exc)


def _serialize_result(result: AnalyzerResult) -> dict:
    """Convert an AnalyzerResult to a JSON-safe dict.

    Args:
        result: The analyzer result dataclass.

    Returns:
        Dict with enum values converted to strings.
    """
    d = asdict(result)
    d["status"] = result.status.value
    return d


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def scan_url(
    url: str,
    config: dict[str, Any],
    passive_only: bool = False,
    screenshot_dir: str = "",
    on_event: EventCallback = None,
    interactive: bool = False,
    human_present: bool = False,
) -> ScanReport:
    """Run all analyzers against the URL and produce a ScanReport.

    Non-browser analyzers run concurrently in a thread pool while
    browser-dependent analyzers share a single Playwright browser and
    run sequentially (Playwright's sync API is greenlet-bound).

    The browser is **persistent** across scans - it is created on the
    first call and reused thereafter, eliminating 2-5 seconds of launch
    overhead per scan.

    Args:
        url: The URL to analyze.
        config: The loaded SOC Box configuration dictionary.
        passive_only: If True, run lexical-only mode (no network/browser analyzers).
        screenshot_dir: Directory to save screenshots. Empty string disables.
        on_event: Optional callback for streaming events (SSE).
        interactive: If True, run the browser on-screen and pause on an
            unsolvable CAPTCHA so the operator can solve it by hand. CLI /
            local single-scan use.
        human_present: If True, an analyst is watching this scan in the web UI
            and can solve an un-automatable CAPTCHA live via the noVNC takeover.
            Set only for single interactive web scans - never for bulk, agent,
            or async scans, which must not block on a human.

    Returns:
        A completed ScanReport with scores and findings.
    """
    # These browser behaviours are thread-local, set per scan (the scan's
    # browser work runs on this thread). Reset any solved-CAPTCHA state from a
    # previous scan so cookies never leak across URLs.
    set_interactive_mode(interactive)
    set_human_present(human_present)
    set_solve_timeout_ms(
        config.get("interactive", {}).get("session_timeout_ms", 180_000)
    )
    reset_solved_state()
    # Emit "action_required" to the stream when a scan hits a CAPTCHA gate, so
    # the web UI can desktop-notify the analyst + open the live solver. No-op
    # for headless/agent scans.
    set_action_notifier(
        (lambda info: _emit(on_event, "action_required", info)) if on_event else None
    )

    passive_allowed_analyzers = {
        # Passive mode is lexical-only: no HTTP/DNS/feed/browser/download calls.
        "URL Lexical Analysis",
    }

    scoring_weights = config.get("scoring", {}).get("weights", {})

    # Separate analyzers into three groups:
    # 1. thread_analyzers: fully thread-safe, run in parallel thread pool
    # 2. browser_analyzers: need Playwright, run sequentially on main thread
    # 3. deferred_analyzers: run in thread pool first (requests-based) but
    #    get a browser-fallback pass on the main thread afterward
    thread_analyzers: list[Any] = []
    browser_analyzers: list[Any] = []
    deferred_analyzers: list[Any] = []
    skipped_results: list[AnalyzerResult] = []

    for analyzer_cls in ALL_ANALYZERS:
        analyzer = analyzer_cls()

        # Apply configured analyzer weights so scoring policy lives in config,
        # not hard-coded class constants.
        weight_key = _ANALYZER_WEIGHT_KEYS.get(analyzer.name)
        if weight_key is not None:
            configured_weight = scoring_weights.get(weight_key)
            if isinstance(configured_weight, (int, float)):
                analyzer.weight = float(configured_weight)

        if passive_only and analyzer.name not in passive_allowed_analyzers:
            skipped_results.append(
                AnalyzerResult(
                    analyzer_name=analyzer.name,
                    status=AnalyzerStatus.SKIPPED,
                    score=0.0,
                    max_weight=analyzer.weight,
                    error_message=(
                        "Skipped (passive-only mode: network/browser analyzers disabled)"
                    ),
                )
            )
        elif analyzer.name in _BROWSER_ANALYZERS:
            browser_analyzers.append(analyzer)
        elif analyzer.name in _DEFERRED_BROWSER_ANALYZERS:
            deferred_analyzers.append(analyzer)
        else:
            thread_analyzers.append(analyzer)

    # Get or create the persistent shared browser
    shared_browser = None
    if not passive_only:
        try:
            _pw, shared_browser = _get_browser(url, interactive=interactive)
        except Exception as exc:
            logger.warning("Failed to get browser: %s", exc)

    # Run thread-safe analyzers in parallel AND browser analyzers
    # sequentially, overlapping the two groups.
    # Screenshot capture is folded into this call (after Page Content).
    scan_meta = _run_all_analyzers(
        thread_analyzers, browser_analyzers,
        url, config, shared_browser,
        screenshot_dir=screenshot_dir,
        passive_only=passive_only,
        on_event=on_event,
    )

    # Deferred analyzers run on the main thread with the browser after
    # all other analyzers have finished.  This gives them access to
    # the shared Playwright browser without blocking the thread pool.
    for analyzer in deferred_analyzers:
        da_analyzer, da_result = _run_analyzer(
            analyzer, url, config, shared_browser,
        )
        scan_meta["analyzer_results"].append(da_result)
        _extract_metadata(da_analyzer, da_result, scan_meta)
        _emit(on_event, "analyzer", {"result": _serialize_result(da_result)})

        # Emit specialised events for deferred analyzers
        if da_analyzer.name == "Download Analysis" and scan_meta.get("file_download"):
            _emit(on_event, "file_download", {
                "info": asdict(scan_meta["file_download"]),
            })

    analyzer_results = skipped_results + scan_meta["analyzer_results"]

    screenshot_path = scan_meta.get("screenshot_path", "")

    overall_score, risk_category, confidence = calculate_score(
        analyzer_results, scan_meta["feed_results"], config,
    )

    # Override generic labels when the primary threat is a file download -
    # "Malicious File Download" or "Suspicious File Download" is more
    # accurate than "Malicious" for payload-delivery URLs.
    file_dl = scan_meta.get("file_download")
    if file_dl and file_dl.detected:
        # If the file hash has VT detections, it's confirmed malicious
        # regardless of the composite score (the URL-level feeds may not
        # have indexed the campaign yet).
        file_has_vt_detections = file_dl.vt_detections > 0

        if risk_category == RiskCategory.MALICIOUS or file_has_vt_detections:
            risk_category = RiskCategory.MALICIOUS_DOWNLOAD
            confidence = 100.0
            # Ensure score reflects malicious classification
            malicious_min = config.get("scoring", {}).get(
                "thresholds", {},
            ).get("malicious", 60)
            overall_score = max(overall_score, float(malicious_min))
        else:
            # Download detected but no VT hits on the file - suspicious.
            risk_category = RiskCategory.SUSPICIOUS_DOWNLOAD
            safe_max = config.get("scoring", {}).get(
                "thresholds", {},
            ).get("safe", 25) + 1
            overall_score = max(overall_score, float(safe_max))

    # Capture multi-screenshots (initial + CTA click)
    multi_screenshots: dict[str, str | None] = {
        "initial": None,
        "initial_url": None,
        "cta": None,
        "cta_url": None,
        "cta_text": None,
    }
    if screenshot_dir and not passive_only:
        try:
            multi_screenshots = capture_multi_screenshots(
                url, Path(screenshot_dir), config, browser=shared_browser,
            )
            _emit(on_event, "multi_screenshots", multi_screenshots)
        except Exception as exc:
            logger.error("Multi-screenshot capture failed: %s", exc)

    recommendation = _build_recommendation(risk_category)

    # Classify attack techniques (ClickFix, encoded command, phishing, ...).
    # Orthogonal to the risk verdict - a URL may carry several, or none.
    classifications = classify(
        url=url,
        page_text=scan_meta.get("page_text", ""),
        scripts=scan_meta.get("scripts", []),
        findings=[f for r in analyzer_results for f in r.findings],
        file_download=scan_meta.get("file_download"),
        redirect_chain=scan_meta.get("redirect_chain", []),
    )

    # Per-analyzer contribution breakdown for the analyst-facing table.
    breakdown = score_breakdown(
        analyzer_results, scan_meta["feed_results"], config,
    )

    # Emit final score event
    _emit(on_event, "score", {
        "overall_score": overall_score,
        "confidence": confidence,
        "risk_category": risk_category.value,
        "recommendation": recommendation,
    })

    _emit(on_event, "classifications", {
        "classifications": [asdict(c) for c in classifications],
    })

    _emit(on_event, "score_breakdown", breakdown)

    return ScanReport(
        url=url,
        overall_score=overall_score,
        risk_category=risk_category,
        confidence=confidence,
        analyzer_results=analyzer_results,
        feed_results=scan_meta["feed_results"],
        redirect_chain=scan_meta["redirect_chain"],
        recommendation=recommendation,
        timestamp=datetime.now(timezone.utc).isoformat(),
        screenshot_path=screenshot_path,
        discovered_links=scan_meta["discovered_links"],
        file_download=scan_meta["file_download"],
        multi_screenshots=multi_screenshots,
        threat_classifications=classifications,
        score_breakdown=breakdown,
        final_url=(
            multi_screenshots.get("initial_url")
            or (scan_meta["redirect_chain"][-1] if scan_meta["redirect_chain"] else "")
            or url
        ),
        page_text=scan_meta.get("page_text", ""),
    )


def _run_analyzer(
    analyzer: Any,
    url: str,
    config: dict[str, Any],
    browser: Any = None,
) -> tuple[Any, AnalyzerResult]:
    """Run a single analyzer with error handling.

    Args:
        analyzer: The analyzer instance to run.
        url: The URL to analyze.
        config: The loaded configuration dictionary.
        browser: Optional shared Playwright Browser instance.

    Returns:
        Tuple of (analyzer_instance, AnalyzerResult).
    """
    try:
        result = analyzer.analyze(url, config, browser=browser)
        return analyzer, result
    except Exception as e:
        return analyzer, AnalyzerResult(
            analyzer_name=analyzer.name,
            status=AnalyzerStatus.ERROR,
            score=0.0,
            max_weight=analyzer.weight,
            error_message=str(e),
        )


def _run_all_analyzers(
    thread_analyzers: list[Any],
    browser_analyzers: list[Any],
    url: str,
    config: dict[str, Any],
    browser: Any,
    screenshot_dir: str = "",
    passive_only: bool = False,
    on_event: EventCallback = None,
) -> dict[str, Any]:
    """Run thread-safe analyzers in a thread pool while running browser
    analyzers sequentially on the current thread.

    The two groups run concurrently: the thread pool handles network I/O
    analyzers (URL lexical, WHOIS, SSL, HTTP, threat feeds, download)
    while the main thread drives Playwright for browser-based analyzers.

    Screenshot capture is performed right after the first browser analyzer
    (Page Content) completes, while the page is freshly loaded. This
    overlaps with the thread pool work and avoids adding time at the end.

    Args:
        thread_analyzers: Analyzers safe to run in worker threads.
        browser_analyzers: Analyzers that need the Playwright browser.
        url: The URL to analyze.
        config: The loaded configuration dictionary.
        browser: Shared Playwright Browser instance (may be None).
        screenshot_dir: Directory for screenshots (empty disables).
        passive_only: Whether we're in passive-only mode.
        on_event: Optional callback for streaming events.

    Returns:
        Dict with keys: analyzer_results, feed_results, redirect_chain,
        discovered_links, file_download, screenshot_path.
    """
    meta: dict[str, Any] = {
        "analyzer_results": [],
        "feed_results": [],
        "redirect_chain": [],
        "discovered_links": [],
        "file_download": None,
        "screenshot_path": "",
        "page_text": "",
        "scripts": [],
    }

    # Submit thread-safe analyzers to the pool
    futures: dict[concurrent.futures.Future, Any] = {}
    max_workers = max(len(thread_analyzers), 1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for analyzer in thread_analyzers:
            future = executor.submit(
                _run_analyzer, analyzer, url, config,
            )
            futures[future] = analyzer

        # While threads are running, execute browser analyzers sequentially
        # on the current thread (Playwright requires this).
        for i, analyzer in enumerate(browser_analyzers):
            ba_analyzer, ba_result = _run_analyzer(
                analyzer, url, config, browser,
            )
            meta["analyzer_results"].append(ba_result)
            _extract_metadata(ba_analyzer, ba_result, meta)
            _emit(on_event, "analyzer", {"result": _serialize_result(ba_result)})

            # After the first browser analyzer (Page Content), capture
            # the screenshot while the page state is fresh - before
            # Link Discovery clicks around and changes the page.
            if i == 0 and screenshot_dir and not passive_only:
                try:
                    result_path = capture_screenshot(
                        url, Path(screenshot_dir), config, browser=browser,
                    )
                    if result_path:
                        meta["screenshot_path"] = str(result_path)
                        _emit(on_event, "screenshot", {
                            "filename": Path(result_path).name,
                        })
                except Exception as exc:
                    logger.error("Screenshot failed: %s", exc)
                    _emit(on_event, "screenshot", {"filename": ""})

        # Collect thread pool results
        for future in concurrent.futures.as_completed(futures):
            analyzer, result = future.result()
            meta["analyzer_results"].append(result)
            _extract_metadata(analyzer, result, meta)
            _emit(on_event, "analyzer", {"result": _serialize_result(result)})

            # Emit specialised events when thread-pool analyzers complete
            if analyzer.name == "Threat Feed Integration":
                feed_dicts = [asdict(f) for f in meta.get("feed_results", [])]
                _emit(on_event, "feed_results", {"feeds": feed_dicts})
            if analyzer.name == "HTTP Response Analysis" and meta.get("redirect_chain"):
                _emit(on_event, "redirect_chain", {
                    "chain": meta["redirect_chain"],
                })

    return meta


def _extract_metadata(
    analyzer: Any,
    result: AnalyzerResult,
    meta: dict[str, Any],
) -> None:
    """Extract side-channel data from specific analyzers.

    Mutates the meta dict in place.

    Args:
        analyzer: The analyzer instance that produced the result.
        result: The AnalyzerResult from the analyzer.
        meta: Mutable dict holding feed_results, redirect_chain, etc.
    """
    if analyzer.name == "HTTP Response Analysis":
        for finding in result.findings:
            if finding.description.startswith("Redirect chain:"):
                chain_str = finding.description.replace(
                    "Redirect chain: ", "",
                )
                meta["redirect_chain"] = [
                    u.strip() for u in chain_str.split(" -> ")
                ]

    if analyzer.name == "Threat Feed Integration":
        meta["feed_results"] = list(
            getattr(analyzer, "last_feed_results", []),
        )

    if analyzer.name == "Link Discovery Analysis":
        meta["discovered_links"] = list(
            getattr(analyzer, "last_discovered_links", []),
        )

    if analyzer.name == "Download Analysis":
        meta["file_download"] = getattr(analyzer, "last_file_info", None)

    if analyzer.name == "Page Content Analysis":
        meta["page_text"] = getattr(analyzer, "page_text", "")
        meta["scripts"] = list(getattr(analyzer, "scripts", []))


def _build_recommendation(category: RiskCategory) -> str:
    """Generate a human-readable recommendation based on risk category.

    Args:
        category: The RiskCategory enum value.

    Returns:
        A recommendation string for the analyst.
    """
    recommendations = {
        RiskCategory.SAFE: "No significant threat indicators detected.",
        RiskCategory.UNCERTAIN: "Mixed signals detected.",
        RiskCategory.MALICIOUS: (
            "This URL is classified as malicious."
        ),
        RiskCategory.MALICIOUS_DOWNLOAD: (
            "This URL delivers a malicious file download."
        ),
        RiskCategory.SUSPICIOUS_DOWNLOAD: (
            "This URL delivers a suspicious file download."
        ),
    }
    return recommendations.get(category, "Unable to determine risk level.")
