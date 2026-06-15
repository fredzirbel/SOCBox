"""FastAPI web application for IRIS."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests as http_requests
import tldextract
import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse

from iris.config import get_api_key, load_config
from iris.scanner import scan_url, shutdown_browser
from iris.web.defang import defang as defang_url
from iris.web.osint import generate_osint_links

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_WEB_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _WEB_DIR.parent.parent.parent
_SCREENSHOT_DIR = _PROJECT_ROOT / "screenshots"

# ---------------------------------------------------------------------------
# Dedicated scan executor (bounded worker pool)
# ---------------------------------------------------------------------------
# Each worker thread gets its own persistent Playwright browser via
# thread-local storage (see scanner._get_browser).  This allows
# concurrent scans while respecting Playwright's greenlet-bound API.
_scan_executor = ThreadPoolExecutor(
    max_workers=3, thread_name_prefix="iris-scan",
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """FastAPI lifespan handler for startup/shutdown tasks.

    On shutdown: close all persistent Playwright browsers across worker
    threads and shut down the executor pool.
    """
    yield
    # Shutdown: close all browsers (shutdown_browser is thread-safe now)
    try:
        shutdown_browser()
    except Exception:
        pass
    _scan_executor.shutdown(wait=False)


app = FastAPI(title="IRIS", version="0.1.0", lifespan=_lifespan)

templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))


def _static_version() -> str:
    """Cache-busting token for static assets.

    Returns the latest mtime of the CSS/JS bundles, appended to their URLs as
    ``?v=``. It changes whenever those files change (and on each image
    rebuild), so browsers fetch fresh assets instead of serving a stale cached
    stylesheet after a redesign.
    """
    static_dir = _WEB_DIR / "static"
    latest = 0.0
    for name in ("style.css", "theme.js"):
        path = static_dir / name
        if path.exists():
            latest = max(latest, path.stat().st_mtime)
    return str(int(latest))


templates.env.globals["static_v"] = _static_version()

# Severity ordering for findings: highest priority first
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_by_severity(findings: list) -> list:
    """Sort findings by severity (critical first, info last).

    Args:
        findings: List of Finding dataclass instances or dicts.

    Returns:
        A new list sorted by severity priority.
    """
    def _get_severity(f: Any) -> int:
        sev = f.get("severity", "") if isinstance(f, dict) else getattr(f, "severity", "")
        return _SEVERITY_ORDER.get(sev, 5)

    return sorted(findings, key=_get_severity)


templates.env.filters["sort_by_severity"] = _sort_by_severity
templates.env.filters["defang"] = defang_url


def _filesizeformat(value: int) -> str:
    """Format a byte count as a human-readable file size.

    Args:
        value: Size in bytes.

    Returns:
        Human-readable size string (e.g. '1.5 MB').
    """
    if value < 1024:
        return f"{value} B"
    elif value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    else:
        return f"{value / (1024 * 1024):.1f} MB"


templates.env.filters["filesizeformat"] = _filesizeformat

# Serve CSS/JS static assets
app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")), name="static")

# Serve screenshot images
_SCREENSHOT_DIR.mkdir(exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=str(_SCREENSHOT_DIR)), name="screenshots")

# ---------------------------------------------------------------------------
# In-memory scan store with disk-backed cache
# ---------------------------------------------------------------------------
_scans: dict[str, dict[str, Any]] = {}
_bulk_scans: dict[str, dict[str, Any]] = {}
_scans_lock = threading.RLock()
_bulk_scans_lock = threading.RLock()
_CACHE_FILE = _SCREENSHOT_DIR / "scan_cache.json"
_BULK_CACHE_FILE = _SCREENSHOT_DIR / "bulk_cache.json"
_CACHE_TTL = 86400  # 24 hours in seconds

logger = logging.getLogger(__name__)


def _serialize_scans() -> list[dict]:
    """Convert the in-memory scan store to JSON-serialisable dicts.

    Returns:
        List of scan entry dicts with all dataclass fields flattened.
    """

    entries = []
    with _scans_lock:
        scan_entries = list(_scans.values())

    for entry in scan_entries:
        d = {
            "scan_id": entry["scan_id"],
            "domain": entry["domain"],
            "ip": entry["ip"],
            "screenshot_filename": entry["screenshot_filename"],
            "report": asdict(entry["report"]),
        }
        # Store enum values as strings for JSON
        d["report"]["risk_category"] = entry["report"].risk_category.value
        for ar in d["report"]["analyzer_results"]:
            ar["status"] = ar["status"].value if hasattr(ar["status"], "value") else ar["status"]
        entries.append(d)
    return entries


def _deserialize_scans(entries: list[dict]) -> dict[str, dict[str, Any]]:
    """Rebuild the in-memory scan store from cached JSON dicts.

    Args:
        entries: List of serialised scan entry dicts from disk.

    Returns:
        Dict keyed by scan_id with full dataclass objects restored.
    """
    from iris.models import (
        AnalyzerResult,
        AnalyzerStatus,
        DiscoveredLink,
        FeedResult,
        FileDownloadInfo,
        Finding,
        RiskCategory,
        ScanReport,
    )

    # Build reverse lookup for enums
    _rc_map = {e.value: e for e in RiskCategory}
    # Legacy compatibility for cached scans from before the scoring overhaul
    _rc_map["Suspicious"] = RiskCategory.UNCERTAIN
    _rc_map["Likely Phishing"] = RiskCategory.UNCERTAIN
    _rc_map["Confirmed Phishing"] = RiskCategory.MALICIOUS
    _as_map = {e.value: e for e in AnalyzerStatus}

    scans = {}
    for entry in entries:
        try:
            rd = entry["report"]

            analyzer_results = []
            for ar in rd.get("analyzer_results", []):
                findings = [Finding(**f) for f in ar.get("findings", [])]
                analyzer_results.append(AnalyzerResult(
                    analyzer_name=ar["analyzer_name"],
                    status=_as_map.get(ar["status"], AnalyzerStatus.COMPLETED),
                    score=ar["score"],
                    max_weight=ar["max_weight"],
                    findings=findings,
                    error_message=ar.get("error_message", ""),
                ))

            feed_results = [
                FeedResult(
                    feed_name=fr["feed_name"],
                    matched=fr["matched"],
                    details=fr.get("details", ""),
                    raw_response=fr.get("raw_response", {}),
                    display_order=fr.get("display_order", 99),
                )
                for fr in rd.get("feed_results", [])
            ]

            discovered_links = [
                DiscoveredLink(**dl)
                for dl in rd.get("discovered_links", [])
            ]

            file_download = None
            fd = rd.get("file_download")
            if fd:
                file_download = FileDownloadInfo(**fd)

            report = ScanReport(
                url=rd["url"],
                overall_score=rd["overall_score"],
                risk_category=_rc_map.get(rd["risk_category"], RiskCategory.SAFE),
                confidence=rd.get("confidence", 50.0),
                analyzer_results=analyzer_results,
                feed_results=feed_results,
                redirect_chain=rd.get("redirect_chain", []),
                recommendation=rd.get("recommendation", ""),
                timestamp=rd.get("timestamp", ""),
                screenshot_path=rd.get("screenshot_path", ""),
                osint_links=rd.get("osint_links", []),
                resolved_ip=rd.get("resolved_ip", ""),
                discovered_links=discovered_links,
                file_download=file_download,
            )

            scans[entry["scan_id"]] = {
                "scan_id": entry["scan_id"],
                "report": report,
                "domain": entry.get("domain", ""),
                "ip": entry.get("ip", ""),
                "screenshot_filename": entry.get("screenshot_filename", ""),
            }
        except Exception as exc:
            logger.warning("Skipping corrupt cache entry %s: %s", entry.get("scan_id"), exc)
            continue

    return scans


def _prune_expired(scans: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Remove scan entries older than the cache TTL.

    Args:
        scans: The scan store dict.

    Returns:
        A new dict with only non-expired entries.
    """
    now = datetime.now(timezone.utc)
    pruned = {}
    for scan_id, entry in scans.items():
        ts = entry["report"].timestamp
        try:
            scan_time = datetime.fromisoformat(ts)
            if (now - scan_time).total_seconds() < _CACHE_TTL:
                pruned[scan_id] = entry
        except (ValueError, TypeError):
            pruned[scan_id] = entry  # Keep entries with unparseable timestamps
    return pruned


def _load_cache() -> None:
    """Load scan results from the cache file on disk.

    Populates ``_scans`` with entries that are still within the TTL window.
    Silently ignores missing or corrupt cache files.
    """
    global _scans
    if not _CACHE_FILE.exists():
        return
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        with _scans_lock:
            _scans = _prune_expired(_deserialize_scans(data))
        logger.info("Loaded %d cached scan(s) from disk.", len(_scans))
    except Exception as exc:
        logger.warning("Failed to load scan cache: %s", exc)


def _save_cache() -> None:
    """Persist the current scan store to disk atomically.

    Prunes expired entries first, then writes to a temporary file and
    renames to avoid corruption on crash.
    """
    global _scans
    try:
        with _scans_lock:
            _scans = _prune_expired(_scans)
        payload = json.dumps(_serialize_scans(), default=str, ensure_ascii=False)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(_SCREENSHOT_DIR), suffix=".tmp", prefix="scan_cache_",
        )
        closed = False
        try:
            os.write(fd, payload.encode("utf-8"))
            os.close(fd)
            closed = True
            os.replace(tmp_path, str(_CACHE_FILE))
        except Exception:
            if not closed:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
    except Exception as exc:
        logger.warning("Failed to save scan cache: %s", exc)


# ---------------------------------------------------------------------------
# Bulk scan session cache
# ---------------------------------------------------------------------------


def _load_bulk_cache() -> None:
    """Load bulk scan sessions from disk."""
    global _bulk_scans
    if not _BULK_CACHE_FILE.exists():
        return
    try:
        data = json.loads(_BULK_CACHE_FILE.read_text(encoding="utf-8"))
        now = datetime.now(timezone.utc)
        with _bulk_scans_lock:
            for bs in data:
                try:
                    ts = datetime.fromisoformat(bs["created"])
                    if (now - ts).total_seconds() < _CACHE_TTL:
                        _bulk_scans[bs["bulk_id"]] = bs
                except (ValueError, TypeError, KeyError):
                    continue
        logger.info("Loaded %d cached bulk session(s) from disk.", len(_bulk_scans))
    except Exception as exc:
        logger.warning("Failed to load bulk cache: %s", exc)


def _save_bulk_cache() -> None:
    """Persist bulk scan sessions to disk atomically."""
    try:
        now = datetime.now(timezone.utc)
        pruned = {}
        with _bulk_scans_lock:
            bulk_items = list(_bulk_scans.items())
        for bid, bs in bulk_items:
            try:
                ts = datetime.fromisoformat(bs["created"])
                if (now - ts).total_seconds() < _CACHE_TTL:
                    pruned[bid] = bs
            except (ValueError, TypeError):
                pruned[bid] = bs
        payload = json.dumps(list(pruned.values()), default=str, ensure_ascii=False)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(_SCREENSHOT_DIR), suffix=".tmp", prefix="bulk_cache_",
        )
        closed = False
        try:
            os.write(fd, payload.encode("utf-8"))
            os.close(fd)
            closed = True
            os.replace(tmp_path, str(_BULK_CACHE_FILE))
        except Exception:
            if not closed:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
    except Exception as exc:
        logger.warning("Failed to save bulk cache: %s", exc)


# Hydrate from disk on startup
_load_cache()
_load_bulk_cache()

# ---------------------------------------------------------------------------
# Configuration (loaded once at startup)
# ---------------------------------------------------------------------------
_config: dict[str, Any] = load_config()


def _resolve_ip(url: str) -> str:
    """Attempt to resolve the domain in *url* to an IP address.

    Uses the shared DNS utility which falls back to DNS-over-HTTPS
    when the system resolver blocks the domain.

    Args:
        url: The URL whose domain should be resolved.

    Returns:
        The resolved IPv4 address string, or empty string on failure.
    """
    from iris.dns_util import resolve_hostname

    return resolve_hostname(url)


# ---------------------------------------------------------------------------
# SSE streaming infrastructure
# ---------------------------------------------------------------------------
# Maps scan_id -> asyncio.Queue of (event_type, data) tuples for active scans.
_active_streams: dict[str, asyncio.Queue] = {}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Render the home page with the URL input form."""
    with _scans_lock:
        recent = list(_scans.values())[-10:]
    recent.reverse()
    return templates.TemplateResponse(
        request,
        "index.html",
        {"recent_scans": recent},
    )


@app.post("/scan")
def scan(request: Request, url: str = Form(...)) -> RedirectResponse:
    """Accept a URL, run the IRIS scan, and redirect to results.

    This is a sync handler (not async) so FastAPI runs it in a threadpool.
    The scan itself is dispatched to the dedicated worker pool executor
    where each worker thread has its own persistent Playwright browser.

    Args:
        request: The incoming HTTP request.
        url: The URL submitted via form.

    Returns:
        A redirect to the results page for this scan.
    """
    # Normalise URL scheme
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    scan_id = uuid.uuid4().hex[:12]

    # Run the scan on the dedicated executor thread (browser persistence)
    future = _scan_executor.submit(
        scan_url,
        url=url,
        config=_config,
        passive_only=False,
        screenshot_dir=str(_SCREENSHOT_DIR),
    )
    report = future.result()  # Block until complete

    # Resolve IP & generate OSINT links
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    ip = _resolve_ip(url)

    report.resolved_ip = ip
    report.osint_links = generate_osint_links(url, domain, ip)

    # Derive screenshot filename for the template (relative to /screenshots/)
    screenshot_filename = ""
    if report.screenshot_path:
        screenshot_filename = Path(report.screenshot_path).name

    with _scans_lock:
        _scans[scan_id] = {
            "scan_id": scan_id,
            "report": report,
            "domain": domain,
            "ip": ip,
            "screenshot_filename": screenshot_filename,
        }

    _save_cache()

    return RedirectResponse(url=f"/results/{scan_id}", status_code=303)


@app.post("/api/scan")
async def api_scan(request: Request) -> JSONResponse:
    """Start a scan in the background and return the scan_id immediately.

    The client should navigate to /results/{scan_id}?stream=1 and
    connect to /stream/{scan_id} for real-time SSE events.

    Args:
        request: The incoming HTTP request with JSON body.

    Returns:
        JSON with the scan_id.
    """
    body = await request.json()
    raw_url = (body.get("url") or "").strip()
    if not raw_url:
        return JSONResponse({"error": "URL required"}, status_code=400)

    url = raw_url
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    scan_id = uuid.uuid4().hex[:12]

    # Resolve metadata early (fast, <1s)
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    ip = _resolve_ip(url)
    osint_links = generate_osint_links(url, domain, ip)

    # Create event queue for this scan
    event_queue: asyncio.Queue = asyncio.Queue()
    _active_streams[scan_id] = event_queue

    loop = asyncio.get_event_loop()

    def on_event(event_type: str, data: dict) -> None:
        """Thread-safe callback that puts events on the async queue."""
        loop.call_soon_threadsafe(event_queue.put_nowait, (event_type, data))

    def run_scan() -> None:
        """Run the full scan on the dedicated executor thread."""
        try:
            # Emit metadata + OSINT immediately
            on_event("metadata", {
                "scan_id": scan_id,
                "url": url,
                "domain": domain,
                "ip": ip,
            })
            on_event("osint", {"links": osint_links})

            report = scan_url(
                url=url,
                config=_config,
                passive_only=False,
                screenshot_dir=str(_SCREENSHOT_DIR),
                on_event=on_event,
            )

            report.resolved_ip = ip

            # Regenerate OSINT links now that we have the redirect chain
            osint_final = generate_osint_links(
                url, domain, ip,
                redirect_chain=report.redirect_chain,
            )
            report.osint_links = osint_final

            # Re-emit OSINT links so the streaming UI gets redirect entries
            on_event("osint", {"links": osint_final})

            screenshot_filename = ""
            if report.screenshot_path:
                screenshot_filename = Path(report.screenshot_path).name

            with _scans_lock:
                _scans[scan_id] = {
                    "scan_id": scan_id,
                    "report": report,
                    "domain": domain,
                    "ip": ip,
                    "screenshot_filename": screenshot_filename,
                }
            _save_cache()

        except Exception as exc:
            logger.error("Scan failed for %s: %s", url, exc)
            on_event("error", {"message": str(exc)})
        finally:
            on_event("complete", {})
            # Schedule cleanup of the event queue after 60 seconds
            loop.call_soon_threadsafe(
                loop.call_later,
                60,
                lambda: _active_streams.pop(scan_id, None),
            )

    _scan_executor.submit(run_scan)

    return JSONResponse({"scan_id": scan_id, "url": url})


@app.get("/stream/{scan_id}")
async def stream(scan_id: str) -> StreamingResponse:
    """SSE endpoint that streams scan events in real time.

    Args:
        scan_id: The unique scan identifier.

    Returns:
        A streaming response with text/event-stream content type.
    """
    event_queue = _active_streams.get(scan_id)

    if event_queue is None:
        # Scan may already be complete
        with _scans_lock:
            in_scans = scan_id in _scans
        if in_scans:
            async def done_stream():
                yield "event: already_complete\ndata: {}\n\n"
            return StreamingResponse(
                done_stream(), media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        async def error_stream():
            yield 'event: error\ndata: {"message": "Scan not found"}\n\n'
        return StreamingResponse(
            error_stream(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    async def event_generator():
        while True:
            try:
                event_type, data = await asyncio.wait_for(
                    event_queue.get(), timeout=120,
                )
                yield f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
                if event_type == "complete":
                    break
            except asyncio.TimeoutError:
                # Send keepalive comment to prevent connection drop
                yield ": keepalive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/results/{scan_id}", response_class=HTMLResponse)
async def results(request: Request, scan_id: str) -> HTMLResponse:
    """Render the full scan report page.

    Supports two modes:
      - **Streaming** (``?stream=1``): renders a skeleton page that connects
        to the SSE endpoint and progressively fills in results.
      - **Static** (default): renders the full results page from stored data.

    Args:
        request: The incoming HTTP request.
        scan_id: The unique identifier for a completed scan.

    Returns:
        The rendered results page, or an error page if scan_id is unknown.
    """
    streaming = request.query_params.get("stream") == "1"
    bulk_id = request.query_params.get("bulk", "")

    if streaming:
        # Render skeleton — scan is likely still in progress
        return templates.TemplateResponse(
            request,
            "results.html",
            {
                "streaming": True,
                "scan_id": scan_id,
                "bulk_id": bulk_id,
            },
        )

    with _scans_lock:
        entry = _scans.get(scan_id)
    if entry is None:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"message": "Scan not found. It may have expired."},
            status_code=404,
        )

    report_json = json.dumps(_report_to_copydata(entry), default=str)

    # Extract multi-screenshot data for the template
    multi_ss = getattr(entry["report"], "multi_screenshots", {}) or {}

    return templates.TemplateResponse(
        request,
        "results.html",
        {
            "streaming": False,
            "report_json": report_json,
            "bulk_id": bulk_id,
            "multi_screenshots": multi_ss,
            **entry,
        },
    )


@app.post("/api/hash-lookup")
async def hash_lookup(request: Request) -> JSONResponse:
    """Look up a SHA-256 hash on VirusTotal and return the results.

    Accepts JSON body ``{"sha256": "..."}`` and returns VT detection stats.
    Used by the File Download Analysis section when an analyst pastes a hash
    they obtained externally (e.g. from a sandbox or PowerShell).

    Args:
        request: The incoming HTTP request with JSON body.

    Returns:
        JSON with detection counts, VT link, and any errors.
    """
    body = await request.json()
    sha256 = (body.get("sha256") or "").strip().lower()

    if not sha256 or not re.match(r"^[a-f0-9]{64}$", sha256):
        return JSONResponse(
            {"error": "Invalid SHA-256 hash. Must be 64 hex characters."},
            status_code=400,
        )

    vt_key = get_api_key(_config, "virustotal")
    if not vt_key:
        return JSONResponse(
            {"error": "No VirusTotal API key configured."},
            status_code=503,
        )

    vt_link = f"https://www.virustotal.com/gui/file/{sha256}"
    timeout = _config.get("requests", {}).get("timeout", 10)

    try:
        resp = http_requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": vt_key},
            timeout=timeout,
        )
    except http_requests.exceptions.RequestException as exc:
        return JSONResponse(
            {"error": f"VirusTotal request failed: {exc}", "vt_link": vt_link},
            status_code=502,
        )

    if resp.status_code == 404:
        return JSONResponse({
            "found": False,
            "vt_link": vt_link,
            "message": "Hash not found in VirusTotal database.",
        })

    if resp.status_code != 200:
        return JSONResponse(
            {"error": f"VirusTotal returned HTTP {resp.status_code}", "vt_link": vt_link},
            status_code=502,
        )

    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get(
        "last_analysis_stats", {},
    )
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = sum(stats.values()) if stats else 0

    attrs = data.get("data", {}).get("attributes", {})
    ptc = attrs.get("popular_threat_classification", {})
    threat_label_list = ptc.get("popular_threat_name", [])
    threat_cat_list = ptc.get("popular_threat_category", [])
    popular_threat_label = threat_label_list[0].get("value", "") if threat_label_list else ""
    threat_category = threat_cat_list[0].get("value", "") if threat_cat_list else ""

    return JSONResponse({
        "found": True,
        "sha256": sha256,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "total": total,
        "detections": malicious + suspicious,
        "vt_link": vt_link,
        "popular_threat_label": popular_threat_label,
        "threat_category": threat_category,
    })


# ---------------------------------------------------------------------------
# API: Get scan results as JSON
# ---------------------------------------------------------------------------


def _serialize_report(entry: dict[str, Any]) -> dict[str, Any]:
    """Convert a scan store entry to a JSON-safe dict with defanged URLs.

    Shared by the REST API endpoints to avoid duplicating serialisation logic.

    Args:
        entry: A scan store entry dict containing the ScanReport.

    Returns:
        JSON-serialisable dict with enum values as strings and defanged URLs.
    """
    report = entry["report"]
    report_dict = asdict(report)
    report_dict["risk_category"] = report.risk_category.value
    for ar in report_dict["analyzer_results"]:
        if hasattr(ar["status"], "value"):
            ar["status"] = ar["status"].value

    report_dict["defanged_url"] = defang_url(report.url)
    report_dict["defanged_redirect_chain"] = [
        defang_url(hop) for hop in report.redirect_chain
    ]

    return {
        "scan_id": entry["scan_id"],
        "domain": entry.get("domain", ""),
        "ip": entry.get("ip", ""),
        "report": report_dict,
    }


@app.get("/api/results/{scan_id}")
async def api_results(scan_id: str) -> JSONResponse:
    """Return completed scan results as structured JSON.

    Intended for SOAR playbooks, automation scripts, and the bulk scan
    "Copy All Reports" feature. Includes defanged URLs for safe sharing.

    Args:
        scan_id: The unique scan identifier.

    Returns:
        JSON representation of the ScanReport with defanged URLs.
    """
    with _scans_lock:
        entry = _scans.get(scan_id)
    if entry is None:
        return JSONResponse(
            {"error": "Scan not found", "scan_id": scan_id},
            status_code=404,
        )

    return JSONResponse(_serialize_report(entry))


@app.post("/api/scan/sync")
async def api_scan_sync(request: Request) -> JSONResponse:
    """Run a synchronous scan and return complete JSON results.

    Blocks until the scan finishes. Intended for SOAR playbooks and
    automation scripts that need a single request/response cycle.

    Callers should set an HTTP timeout of at least 120 seconds since
    scans typically take 30-90 seconds.

    Accepts JSON body: ``{"url": "https://example.com"}``

    Args:
        request: The incoming HTTP request with JSON body.

    Returns:
        JSON with full scan report including defanged URLs.
    """
    body = await request.json()
    raw_url = (body.get("url") or "").strip()
    if not raw_url:
        return JSONResponse({"error": "URL required"}, status_code=400)

    url = raw_url
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    scan_id = uuid.uuid4().hex[:12]

    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    ip = _resolve_ip(url)
    loop = asyncio.get_event_loop()

    def run_scan():
        """Execute the scan on the dedicated executor thread."""
        report = scan_url(
            url=url,
            config=_config,
            passive_only=False,
            screenshot_dir=str(_SCREENSHOT_DIR),
        )
        report.resolved_ip = ip
        report.osint_links = generate_osint_links(
            url, domain, ip,
            redirect_chain=report.redirect_chain,
        )
        return report

    try:
        report = await loop.run_in_executor(_scan_executor, run_scan)
    except Exception as exc:
        return JSONResponse(
            {"error": f"Scan failed: {exc}"},
            status_code=500,
        )

    screenshot_filename = ""
    if report.screenshot_path:
        screenshot_filename = Path(report.screenshot_path).name

    with _scans_lock:
        _scans[scan_id] = {
            "scan_id": scan_id,
            "report": report,
            "domain": domain,
            "ip": ip,
            "screenshot_filename": screenshot_filename,
        }
    _save_cache()

    with _scans_lock:
        entry = _scans[scan_id]
    return JSONResponse(_serialize_report(entry))


# ---------------------------------------------------------------------------
# Report data helper (for Copy Report feature)
# ---------------------------------------------------------------------------


def _report_to_copydata(entry: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-safe dict of report data for the Copy Report feature.

    Pre-serialises findings, feeds, and file download info for safe
    embedding as a JSON blob in the template ``<script>`` tag.

    Args:
        entry: A scan store entry dict.

    Returns:
        Dict suitable for JSON serialisation and clipboard text construction.
    """
    report = entry["report"]

    findings = []
    for ar in report.analyzer_results:
        if ar.status.value == "COMPLETED":
            for f in ar.findings:
                findings.append({
                    "severity": f.severity,
                    "description": f.description,
                    "score": f.score_contribution,
                })

    feed_data = []
    for fr in report.feed_results:
        feed_data.append({
            "feed_name": fr.feed_name,
            "matched": fr.matched,
            "details": fr.details,
        })

    file_dl = None
    if report.file_download and report.file_download.detected:
        file_dl = {
            "filename": report.file_download.filename,
            "sha256": report.file_download.sha256,
            "vt_detections": report.file_download.vt_detections,
            "vt_total_engines": report.file_download.vt_total_engines,
            "popular_threat_label": report.file_download.popular_threat_label,
        }

    return {
        "url": report.url,
        "defanged_url": defang_url(report.url),
        "risk_category": report.risk_category.value,
        "confidence": report.confidence,
        "timestamp": report.timestamp,
        "ip": entry.get("ip", ""),
        "domain": entry.get("domain", ""),
        "recommendation": report.recommendation,
        "redirect_chain": report.redirect_chain,
        "feed_results": feed_data,
        "findings": findings,
        "file_download": file_dl,
    }


# ---------------------------------------------------------------------------
# Escalation report generator
# ---------------------------------------------------------------------------


@app.post("/api/escalation/{scan_id}")
async def api_escalation(scan_id: str, request: Request) -> JSONResponse:
    """Generate a pre-filled escalation report from scan results.

    Accepts optional alert context (UPN, sender, subject, etc.) to
    produce a more complete report.  When alert context is omitted,
    placeholder markers are left for the analyst to fill in.

    Args:
        scan_id: The unique scan identifier.
        request: The incoming HTTP request with optional JSON body.

    Returns:
        JSON with ``escalation_md`` (the markdown report) and
        ``kql_queries`` (list of ready-to-paste KQL queries).
    """
    from iris.web.escalation import generate_escalation, generate_kql_queries

    with _scans_lock:
        entry = _scans.get(scan_id)
    if entry is None:
        return JSONResponse(
            {"error": "Scan not found", "scan_id": scan_id},
            status_code=404,
        )

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass  # No body is fine — alert context is optional

    alert_context = body.get("alert_context") if body else None
    scan_data = _report_to_copydata(entry)

    escalation_md = generate_escalation(scan_data, alert_context)

    # Build KQL queries
    sender_domain = ""
    if alert_context and alert_context.get("sender"):
        sender = alert_context["sender"]
        if "@" in sender:
            sender_domain = sender.split("@", 1)[1]

    kql_queries = generate_kql_queries(
        domain=entry.get("domain", ""),
        url=entry["report"].url,
        sender_domain=sender_domain,
    )

    return JSONResponse({
        "escalation_md": escalation_md,
        "kql_queries": kql_queries,
    })


# ---------------------------------------------------------------------------
# Sender IP enrichment
# ---------------------------------------------------------------------------


@app.post("/api/enrich-ip")
async def api_enrich_ip(request: Request) -> JSONResponse:
    """Enrich a sender IP address with VirusTotal and AbuseIPDB lookups.

    Accepts JSON body ``{"ip": "1.2.3.4"}`` and returns enrichment data.

    Args:
        request: The incoming HTTP request with JSON body.

    Returns:
        JSON with VT and AbuseIPDB enrichment results.
    """
    body = await request.json()
    ip = (body.get("ip") or "").strip()

    if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return JSONResponse(
            {"error": "Invalid IPv4 address."},
            status_code=400,
        )

    results: dict[str, Any] = {
        "ip": ip,
        "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}",
        "abuseipdb_link": f"https://www.abuseipdb.com/check/{ip}",
        "vt": None,
        "abuseipdb": None,
    }

    timeout = _config.get("requests", {}).get("timeout", 10)

    # VirusTotal IP lookup
    vt_key = get_api_key(_config, "virustotal")
    if vt_key:
        try:
            vt_resp = http_requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": vt_key},
                timeout=timeout,
            )
            if vt_resp.status_code == 200:
                vt_data = vt_resp.json()
                attrs = vt_data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results["vt"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()) if stats else 0,
                    "country": attrs.get("country", ""),
                    "as_owner": attrs.get("as_owner", ""),
                    "asn": attrs.get("asn", 0),
                }
        except http_requests.exceptions.RequestException as exc:
            logger.warning("VT IP lookup failed for %s: %s", ip, exc)

    # AbuseIPDB lookup
    abuseipdb_key = get_api_key(_config, "abuseipdb")
    if abuseipdb_key:
        try:
            abuse_resp = http_requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": abuseipdb_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=timeout,
            )
            if abuse_resp.status_code == 200:
                abuse_data = abuse_resp.json().get("data", {})
                results["abuseipdb"] = {
                    "abuse_confidence": abuse_data.get(
                        "abuseConfidenceScore", 0,
                    ),
                    "total_reports": abuse_data.get("totalReports", 0),
                    "country_code": abuse_data.get("countryCode", ""),
                    "isp": abuse_data.get("isp", ""),
                    "domain": abuse_data.get("domain", ""),
                    "is_tor": abuse_data.get("isTor", False),
                }
        except http_requests.exceptions.RequestException as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)

    return JSONResponse(results)


# ---------------------------------------------------------------------------
# Bulk scan page
# ---------------------------------------------------------------------------


@app.get("/bulk", response_class=HTMLResponse)
async def bulk_page(request: Request) -> HTMLResponse:
    """Render the bulk scan page (new or resumed).

    If a ``bulk_id`` query parameter is provided, the page will
    automatically restore the corresponding cached session.

    Args:
        request: The incoming HTTP request.

    Returns:
        The bulk scan HTML page.
    """
    bulk_id = request.query_params.get("id", "")
    bulk_data = None
    with _bulk_scans_lock:
        bulk_entry = _bulk_scans.get(bulk_id) if bulk_id else None
    if bulk_entry is not None:
        bulk_data = json.dumps(bulk_entry, default=str)

    return templates.TemplateResponse(
        request,
        "bulk.html",
        {
            "bulk_restore": bulk_data or "null",
        },
    )


@app.post("/api/bulk")
async def api_bulk_save(request: Request) -> JSONResponse:
    """Create or update a bulk scan session.

    Accepts JSON with bulk_id, scan entries, and URLs. Persists to
    the bulk cache so sessions survive container restarts.

    Args:
        request: The incoming HTTP request with JSON body.

    Returns:
        JSON confirmation with the bulk_id.
    """
    body = await request.json()
    bulk_id = body.get("bulk_id", "")
    if not bulk_id:
        bulk_id = uuid.uuid4().hex[:12]

    with _bulk_scans_lock:
        _bulk_scans[bulk_id] = {
            "bulk_id": bulk_id,
            "urls": body.get("urls", []),
            "results": body.get("results", []),
            "created": body.get("created", datetime.now(timezone.utc).isoformat()),
        }
    _save_bulk_cache()

    return JSONResponse({"bulk_id": bulk_id})


@app.get("/api/bulk/{bulk_id}")
async def api_bulk_get(bulk_id: str) -> JSONResponse:
    """Retrieve a cached bulk scan session.

    Args:
        bulk_id: The unique bulk session identifier.

    Returns:
        JSON with the bulk session data, or 404.
    """
    with _bulk_scans_lock:
        bs = _bulk_scans.get(bulk_id)
    if bs is None:
        return JSONResponse(
            {"error": "Bulk session not found", "bulk_id": bulk_id},
            status_code=404,
        )
    return JSONResponse(bs)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the IRIS web server."""
    import sys

    # Enable auto-reload by default during development so code changes
    # take effect without manually restarting.  Pass --no-reload to disable.
    is_dev = "--no-reload" not in sys.argv
    import os

    host = os.getenv("IRIS_HOST", "0.0.0.0")
    port = int(os.getenv("IRIS_PORT", "8000"))
    uvicorn.run(
        "iris.web.app:app",
        host=host,
        port=port,
        reload=is_dev,
    )


if __name__ == "__main__":
    main()
