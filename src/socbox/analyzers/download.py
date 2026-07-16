"""File download analysis for phishing/malware detection.

Uses a layered detection strategy:
  1. HEAD request Content-Type / Content-Disposition headers.
  2. URL path extension heuristic (e.g. ``/file.zip``).
  3. Streamed GET probe when HEAD is ambiguous but the path looks like a file.
  4. **Playwright browser fallback** — when ``requests`` is blocked (403 /
     Cloudflare challenge / bot detection) but a real browser can trigger the
     download, this layer intercepts the file via Playwright's download event,
     computes the SHA-256, and proceeds with OSINT lookups.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

import requests
import tldextract
from Levenshtein import distance as levenshtein_distance

from socbox.analyzers.base import BaseAnalyzer
from socbox.config import get_api_key
from socbox.dns_util import request_with_doh_fallback
from socbox.feeds.virustotal import scanned_engine_total
from socbox.models import AnalyzerResult, AnalyzerStatus, FileDownloadInfo, Finding

logger = logging.getLogger(__name__)

# Content types that indicate a binary/executable download.
_DOWNLOAD_CONTENT_TYPES = frozenset({
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-msi",
    "application/vnd.microsoft.portable-executable",
    "application/x-dosexec",
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/x-tar",
    "application/gzip",
    "application/x-iso9660-image",
    "application/x-apple-diskimage",
})

# File extensions in the URL path that strongly indicate a download, even when
# the HEAD response returns a misleading Content-Type (e.g. text/html for a
# landing page that auto-triggers a download).
_DOWNLOAD_PATH_EXTENSIONS = frozenset({
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".scr",
    ".dll", ".lnk", ".iso", ".img", ".wsf", ".js",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".dmg", ".pkg", ".deb", ".rpm", ".apk", ".appimage",
})

# Max bytes to download for hashing (10 MB).
_MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024

# Seconds to wait for a browser-triggered download before giving up.
# Many phishing kits show fake "loading" screens for 5-15 seconds before
# delivering the payload, so this needs to be generous — but only when the
# page actually shows download-intent cues. A genuine JS auto-download fires
# within a second or two of load, so a static landing page (the common case:
# credential phishing, fake login, ClickFix) that will never download is
# released after the short window instead of stalling the whole scan.
_BROWSER_DL_WAIT_SEC = 12
_BROWSER_DL_QUICK_SEC = 3

# Visible page-text cues that a (possibly delayed) download is being prepared.
# Their presence justifies waiting the full _BROWSER_DL_WAIT_SEC budget.
_DOWNLOAD_INTENT_CUES = (
    "download will", "your download", "preparing your", "your file is",
    "your file will", "verifying", "please wait", "download starting",
    "starting download", "generating your", "almost ready",
    "click here to download", "download should begin",
)


class DownloadAnalyzer(BaseAnalyzer):
    """Detect and analyze file downloads served by a URL.

    Checks for binary downloads, CDN abuse, suspicious file extensions,
    path-based brand typosquatting, and VirusTotal hash lookups.
    """

    name = "Download Analysis"
    weight = 15.0

    def __init__(self) -> None:
        """Initialize the analyzer with empty file info."""
        self.last_file_info: FileDownloadInfo | None = None

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Check whether the URL serves a file download and analyze it.

        Uses a multi-layer approach: HEAD headers → URL path extension →
        streamed GET probe → Playwright browser download interception.
        The browser fallback catches downloads hidden behind Cloudflare,
        bot-gating, or JS-triggered mechanisms that block ``requests``.

        Args:
            url: The URL to analyze.
            config: The loaded configuration dictionary.
            browser: Optional shared Playwright Browser instance for
                fallback download interception when ``requests`` is blocked.

        Returns:
            AnalyzerResult with download-related findings.
        """
        timeout = config.get("requests", {}).get("timeout", 10)
        user_agent = config.get("requests", {}).get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        verify_ssl = config.get("requests", {}).get("verify_ssl", False)
        headers = {"User-Agent": user_agent}

        # Check whether the URL path itself has a downloadable file extension.
        # Many servers return text/html for HEAD requests on download URLs
        # (e.g. landing pages that auto-trigger the download via JS), so the
        # path extension is a critical secondary signal.
        parsed_early = urlparse(url)
        path_ext = PurePosixPath(parsed_early.path).suffix.lower()
        url_implies_download = path_ext in _DOWNLOAD_PATH_EXTENSIONS

        # HEAD request to check content type without downloading
        head_resp = None
        content_type = ""
        content_disp = ""
        is_attachment = False
        try:
            head_resp = request_with_doh_fallback(
                "HEAD", url, headers=headers, timeout=timeout,
                verify=verify_ssl, allow_redirects=True,
            )
            content_type = head_resp.headers.get("Content-Type", "").lower().split(";")[0].strip()
            content_disp = head_resp.headers.get("Content-Disposition", "")
            is_attachment = "attachment" in content_disp.lower()
        except requests.exceptions.RequestException as e:
            if not url_implies_download:
                self.last_file_info = None
                return AnalyzerResult(
                    analyzer_name=self.name,
                    status=AnalyzerStatus.ERROR,
                    score=0.0,
                    max_weight=self.weight,
                    error_message=f"HEAD request failed: {e}",
                )
            logger.debug("HEAD failed but URL path implies download, proceeding: %s", e)

        # Determine if this is a download via HEAD response headers
        is_download_by_headers = (
            content_type in _DOWNLOAD_CONTENT_TYPES
            or is_attachment
            or (content_type and "text/html" not in content_type and "text/" not in content_type
                and "image/" not in content_type and "application/json" not in content_type
                and "application/xml" not in content_type)
        )

        # When the URL path clearly names a file (e.g. /ext2.zip) but the HEAD
        # response returned text/html, perform a small streamed GET to inspect
        # the *actual* Content-Type delivered with the body.  Many servers only
        # set the correct binary Content-Type on GET, not HEAD.
        if url_implies_download and not is_download_by_headers:
            try:
                probe = request_with_doh_fallback(
                    "GET", url, headers=headers, timeout=timeout,
                    verify=verify_ssl, stream=True,
                )
                probe_ct = probe.headers.get("Content-Type", "").lower().split(";")[0].strip()
                probe_disp = probe.headers.get("Content-Disposition", "")
                probe.close()

                if (probe_ct in _DOWNLOAD_CONTENT_TYPES
                        or "attachment" in probe_disp.lower()
                        or (probe_ct and "text/html" not in probe_ct
                            and "text/" not in probe_ct)):
                    content_type = probe_ct
                    content_disp = probe_disp
                    is_attachment = "attachment" in probe_disp.lower()
                    is_download_by_headers = True
            except requests.exceptions.RequestException:
                pass

        is_download = is_download_by_headers or url_implies_download

        # Detect whether requests was blocked (403, Cloudflare challenge, etc.)
        # so we know when the browser fallback is needed.
        requests_blocked = (
            head_resp is not None and head_resp.status_code in (403, 503)
        )

        # -----------------------------------------------------------------
        # Layer 4 — Playwright browser fallback for detection + hashing.
        # When requests is blocked and headers gave us nothing, use the
        # shared browser to navigate the URL and intercept any download that
        # the real browser triggers.  Also detects Cloudflare phishing
        # interstitials that gate file downloads.
        # -----------------------------------------------------------------
        browser_dl_info: dict[str, Any] | None = None
        temp_download_paths: list[str] = []

        if not is_download and browser is not None:
            browser_dl_info = self._browser_download(url, browser)
            if browser_dl_info:
                is_download = True
                if browser_dl_info.get("path"):
                    temp_download_paths.append(browser_dl_info["path"])
                content_type = browser_dl_info.get("content_type", content_type)
                if browser_dl_info.get("suggested_filename"):
                    content_disp = browser_dl_info["suggested_filename"]

        if not is_download:
            self.last_file_info = None
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.COMPLETED,
                score=0.0,
                max_weight=self.weight,
                findings=[
                    Finding(
                        description="URL does not serve a file download",
                        score_contribution=0.0,
                        severity="info",
                    )
                ],
            )

        # Build file info
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = PurePosixPath(parsed.path)

        # Determine whether Cloudflare blocked the download.
        cf_blocked = (
            browser_dl_info is not None
            and browser_dl_info.get("cloudflare_phishing_block")
        )

        # Resolve filename.  When a browser download captured the file we
        # trust its suggested_filename.  For the Cloudflare-blocked case the
        # "suggested_filename" is just the opaque URL path segment (e.g.
        # "F4lBD64y"), which is NOT the real filename — leave it blank so the
        # template shows "Unknown (behind Cloudflare)" instead.
        has_suggested = (
            browser_dl_info
            and browser_dl_info.get("path")
            and browser_dl_info.get("suggested_filename")
        )
        if has_suggested:
            filename = browser_dl_info["suggested_filename"]
        elif cf_blocked:
            # Don't use the opaque path segment as a filename.
            filename = ""
        else:
            filename = self._extract_filename(content_disp, path)
        extension = self._get_extension(filename, path)

        file_info = FileDownloadInfo(
            detected=True,
            filename=filename,
            extension=extension,
            content_type=content_type,
            hosting_domain=hostname,
            cloudflare_blocked=cf_blocked,
        )

        findings: list[Finding] = []

        # If the browser detected a Cloudflare phishing interstitial gating
        # the download, that is itself a strong signal worth reporting.
        if cf_blocked:
            findings.append(Finding(
                description=(
                    "Cloudflare has flagged this URL as suspected phishing "
                    "(phishing interstitial detected)"
                ),
                score_contribution=40.0,
                severity="critical",
            ))

        # Base finding: download detected
        if browser_dl_info and browser_dl_info.get("path"):
            detection_method = "browser interception"
        elif cf_blocked:
            detection_method = "Cloudflare-gated file download"
        else:
            detection_method = f"Content-Type: {content_type}"
        findings.append(Finding(
            description=f"URL serves a file download ({detection_method})",
            score_contribution=10.0,
            severity="low",
        ))

        # CDN abuse check
        abused_domains = config.get("abused_hosting_domains", [])
        if self._check_abused_host(hostname, abused_domains):
            file_info.is_abused_host = True
            findings.append(Finding(
                description=f"File hosted on commonly-abused domain: {hostname}",
                score_contribution=25.0,
                severity="high",
            ))

        # Suspicious extension in URL path
        suspicious_exts = config.get("suspicious_extensions", [])
        ext_finding = self._check_suspicious_extension(extension, suspicious_exts)
        if ext_finding:
            findings.append(ext_finding)

        # Content-Disposition filename extension check
        if is_attachment and filename:
            disp_ext_finding = self._check_disposition_extension(filename, suspicious_exts)
            if disp_ext_finding:
                findings.append(disp_ext_finding)

        # Path brand typosquatting
        brands = config.get("brands", [])
        typo_finding = self._check_path_typosquatting(parsed.path, brands)
        if typo_finding:
            findings.append(typo_finding)

        # Download file and compute hashes.
        # Try requests first; fall back to browser-captured bytes if blocked.
        sha1, sha256, size_bytes = self._download_and_hash(
            url, headers, timeout, verify_ssl,
        )

        # If requests-based download failed and the browser already captured
        # the file, use that instead.
        if not sha256 and browser_dl_info and browser_dl_info.get("path"):
            sha1, sha256, size_bytes = self._hash_local_file(
                browser_dl_info["path"],
            )

        # If we still have nothing and requests was blocked, try browser now
        # (the browser may not have been tried yet if header detection
        # succeeded but the GET for hashing was blocked).
        if not sha256 and requests_blocked and browser is not None and not browser_dl_info:
            browser_dl_info = self._browser_download(url, browser)
            if browser_dl_info and browser_dl_info.get("path"):
                temp_download_paths.append(browser_dl_info["path"])
                sha1, sha256, size_bytes = self._hash_local_file(
                    browser_dl_info["path"],
                )
                if not filename and browser_dl_info.get("suggested_filename"):
                    filename = browser_dl_info["suggested_filename"]
                    file_info.filename = filename
                    file_info.extension = self._get_extension(filename, path)

        file_info.sha1 = sha1
        file_info.sha256 = sha256
        file_info.size_bytes = size_bytes

        # VirusTotal hash lookup
        if sha256:
            vt_key = get_api_key(config, "virustotal")
            if vt_key:
                vt_finding = self._check_virustotal_hash(
                    sha256, vt_key, timeout, file_info,
                )
                if vt_finding:
                    findings.append(vt_finding)

        self.last_file_info = file_info
        score = min(100.0, sum(f.score_contribution for f in findings))

        for temp_path in temp_download_paths:
            self._cleanup_temp_download(temp_path)

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    def _browser_download(
        self, url: str, browser: Any,
    ) -> dict[str, Any] | None:
        """Use a Playwright browser to navigate to the URL and intercept any
        file download that is triggered.

        This catches downloads behind Cloudflare bot challenges, JS-triggered
        auto-downloads, and servers that return 403 to plain ``requests`` but
        serve files to real browsers.

        When a Cloudflare "Suspected Phishing" interstitial is detected but
        cannot be bypassed (Turnstile fails in automated environments), the
        method still returns a result dict with ``cloudflare_phishing_block``
        set to ``True`` so the caller can treat the block itself as a finding.

        Args:
            url: The URL to navigate to.
            browser: A launched Playwright Browser instance.

        Returns:
            Dict with ``path`` (temp file), ``suggested_filename``,
            ``content_type``, and optionally ``cloudflare_phishing_block``;
            or ``None`` if nothing useful was detected.
        """
        from socbox.browser import (
            _INIT_SCRIPT,
            USER_AGENT,
            get_solved_state,
            is_human_present,
            navigate_with_bypass,
        )

        context = None
        try:
            # Create a dedicated context with downloads explicitly enabled.
            # Replay any CAPTCHA clearance already solved earlier in this scan so
            # a gate solved on the landing page also unlocks the gated download.
            ctx_kwargs: dict[str, Any] = {
                "viewport": {"width": 1280, "height": 720},
                "ignore_https_errors": True,
                "user_agent": USER_AGENT,
                "locale": "en-US",
                "timezone_id": "America/New_York",
                "accept_downloads": True,
            }
            solved_state = get_solved_state()
            if solved_state:
                ctx_kwargs["storage_state"] = solved_state
            context = browser.new_context(**ctx_kwargs)
            context.add_init_script(_INIT_SCRIPT)
            page = context.new_page()

            # Prepare a temp dir for the download
            tmp_dir = tempfile.mkdtemp(prefix="socbox_dl_")

            # Listen for the download event.  We'll store the first one.
            download_info: dict[str, Any] = {}

            def _on_download(download: Any) -> None:
                """Capture the first download event."""
                if download_info:
                    return  # Only capture the first download
                try:
                    suggested = download.suggested_filename
                    save_path = str(Path(tmp_dir) / (suggested or "download"))
                    download.save_as(save_path)
                    download_info["path"] = save_path
                    download_info["suggested_filename"] = suggested or ""
                    download_info["content_type"] = ""
                except Exception as exc:
                    logger.debug("Browser download save failed: %s", exc)

            page.on("download", _on_download)

            # Navigate. When an analyst is present, go through navigate_with_bypass
            # so a CAPTCHA gating the download triggers the live noVNC takeover and
            # the page reloads past the gate. In automated/headless runs use a plain
            # goto so we don't waste the nav budget on a Turnstile that won't solve.
            try:
                if is_human_present():
                    navigate_with_bypass(page, url, timeout_ms=15000)
                else:
                    page.goto(
                        url, wait_until="domcontentloaded", timeout=15000,
                    )
            except Exception as exc:
                logger.debug("Browser navigation failed: %s", exc)
                page.close()
                context.close()
                context = None
                return None

            # Poll for a download event.  Many phishing sites show a fake
            # "loading" or "verifying" page for several seconds before the
            # real download fires (JS setTimeout, fetch-then-blob, etc.), so we
            # poll once per second and return the instant a download arrives.
            #
            # The wait budget is adaptive: a static landing page that will
            # never download (most credential-phishing / ClickFix pages) is
            # released after _BROWSER_DL_QUICK_SEC, while a page that visibly
            # advertises a pending download is given the full window. This
            # keeps the common case fast without missing delayed payloads.
            max_wait = (
                _BROWSER_DL_WAIT_SEC
                if self._page_shows_download_intent(page)
                else _BROWSER_DL_QUICK_SEC
            )
            for _tick in range(max_wait):
                if download_info and download_info.get("path"):
                    break
                page.wait_for_timeout(1000)

            # If a download was intercepted, return it immediately.
            if download_info and download_info.get("path"):
                logger.info(
                    "Browser intercepted download: %s",
                    download_info.get("suggested_filename", "unknown"),
                )
                page.close()
                context.close()
                context = None
                return download_info

            # -----------------------------------------------------------
            # Check for Cloudflare "Suspected Phishing" interstitial.
            # If present, the Turnstile will almost certainly not solve in
            # an automated environment, but the interstitial itself is
            # valuable intelligence and the hidden form fields reveal the
            # original download path.
            # -----------------------------------------------------------
            cf_result = self._check_cloudflare_phishing_page(page)
            page.close()
            context.close()
            context = None

            if cf_result:
                return cf_result

            return None

        except Exception as exc:
            logger.debug("Browser download fallback failed: %s", exc)
            return None
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass

    def _page_shows_download_intent(self, page: Any) -> bool:
        """Return True if the page's visible text advertises a pending download.

        Used to decide whether to wait the full browser-download budget. A page
        that says e.g. "your download will begin shortly" or "verifying" may
        deliver a payload after a delay and is worth waiting on; a plain landing
        page is not, so the poll can exit early.

        Args:
            page: The Playwright page, already navigated.

        Returns:
            True if a download-intent cue is present in the page text.
        """
        try:
            text = page.evaluate(
                "() => (document.body ? document.body.innerText : '')"
                ".toLowerCase().slice(0, 3000)"
            ) or ""
        except Exception as exc:
            logger.debug("Download-intent check failed: %s", exc)
            return False
        return any(cue in text for cue in _DOWNLOAD_INTENT_CUES)

    def _check_cloudflare_phishing_page(
        self, page: Any,
    ) -> dict[str, Any] | None:
        """Inspect the current page for a Cloudflare phishing interstitial.

        Extracts the ``original_path`` hidden field (which names the file the
        user would have downloaded) and returns metadata about the block.

        Args:
            page: A Playwright Page that may be showing a CF interstitial.

        Returns:
            Dict with ``cloudflare_phishing_block``, ``suggested_filename``,
            and ``content_type``; or ``None`` if no interstitial was found.
        """
        try:
            is_cf_phishing = page.evaluate("""() => {
                const title = (document.title || '').toLowerCase();
                const body = document.body
                    ? document.body.innerText.toLowerCase().substring(0, 2000)
                    : '';
                return (
                    (title.includes('suspected phishing') && title.includes('cloudflare'))
                    || (body.includes('suspected phishing') && body.includes('cloudflare'))
                );
            }""")

            if not is_cf_phishing:
                return None

            logger.info("Cloudflare phishing interstitial detected — extracting metadata")

            # Pull the original_path from the hidden form field.
            original_path = page.evaluate("""() => {
                const inp = document.querySelector('input[name="original_path"]');
                return inp ? inp.value : '';
            }""") or ""

            # Derive a filename from the original path (e.g. /api/dl/file.zip → file.zip)
            suggested_filename = ""
            if original_path:
                last_segment = PurePosixPath(original_path).name
                if last_segment:
                    suggested_filename = last_segment

            return {
                "cloudflare_phishing_block": True,
                "suggested_filename": suggested_filename,
                "content_type": "",
                "path": "",  # No file was downloaded
            }

        except Exception as exc:
            logger.debug("Cloudflare interstitial check failed: %s", exc)
            return None

    def _hash_local_file(self, file_path: str) -> tuple[str, str, int]:
        """Compute SHA-1 + SHA-256 hashes of a local file.

        Args:
            file_path: Absolute path to the file on disk.

        Returns:
            Tuple of (sha1_hex, sha256_hex, size_bytes).
        """
        try:
            sha1 = hashlib.sha1(usedforsecurity=False)  # file identity, not crypto
            sha256 = hashlib.sha256()
            total_bytes = 0
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(8192)
                    if not chunk:
                        break
                    sha1.update(chunk)
                    sha256.update(chunk)
                    total_bytes += len(chunk)
                    if total_bytes >= _MAX_DOWNLOAD_BYTES:
                        break
            return sha1.hexdigest(), sha256.hexdigest(), total_bytes
        except Exception as exc:
            logger.debug("Failed to hash local file %s: %s", file_path, exc)
            return "", "", 0

    def _cleanup_temp_download(self, file_path: str) -> None:
        """Delete temporary browser download file and its temp directory.

        Args:
            file_path: Path to the downloaded file created by _browser_download.
        """
        if not file_path:
            return

        try:
            p = Path(file_path)
            if p.exists():
                p.unlink(missing_ok=True)

            parent = p.parent
            if parent.name.startswith("socbox_dl_") and parent.exists():
                shutil.rmtree(parent, ignore_errors=True)
        except Exception as exc:
            logger.debug("Failed to cleanup temp download %s: %s", file_path, exc)

    def _extract_filename(self, content_disp: str, path: PurePosixPath) -> str:
        """Extract filename from Content-Disposition header or URL path.

        Args:
            content_disp: The Content-Disposition header value.
            path: The parsed URL path.

        Returns:
            The extracted filename, or empty string.
        """
        if content_disp:
            match = re.search(r'filename[*]?=["\']?([^"\';\r\n]+)', content_disp, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        if path.name:
            return path.name

        return ""

    def _get_extension(self, filename: str, path: PurePosixPath) -> str:
        """Get file extension from filename or URL path.

        Args:
            filename: The extracted filename.
            path: The parsed URL path.

        Returns:
            The file extension (e.g. ".exe"), or empty string.
        """
        if filename and "." in filename:
            return PurePosixPath(filename).suffix.lower()
        if path.suffix:
            return path.suffix.lower()
        return ""

    def _check_abused_host(self, hostname: str, abused_domains: list[str]) -> bool:
        """Check if hostname matches a commonly-abused hosting domain.

        Args:
            hostname: The hostname to check.
            abused_domains: List of known-abused domain patterns.

        Returns:
            True if hostname matches an abused domain.
        """
        hostname_lower = hostname.lower()
        for domain in abused_domains:
            if hostname_lower == domain.lower() or hostname_lower.endswith("." + domain.lower()):
                return True
        return False

    def _check_suspicious_extension(
        self, extension: str, suspicious_exts: list[str],
    ) -> Finding | None:
        """Check if file extension is suspicious.

        Args:
            extension: The file extension to check.
            suspicious_exts: List of suspicious extensions from config.

        Returns:
            Finding if extension is suspicious.
        """
        if extension and extension in [e.lower() for e in suspicious_exts]:
            return Finding(
                description=f"Suspicious file extension detected: {extension}",
                score_contribution=20.0,
                severity="medium",
            )
        return None

    def _check_disposition_extension(
        self, filename: str, suspicious_exts: list[str],
    ) -> Finding | None:
        """Check Content-Disposition filename for suspicious extension.

        Args:
            filename: The filename from Content-Disposition.
            suspicious_exts: List of suspicious extensions from config.

        Returns:
            Finding if the filename has a suspicious extension.
        """
        ext = PurePosixPath(filename).suffix.lower()
        if ext and ext in [e.lower() for e in suspicious_exts]:
            return Finding(
                description=f"Content-Disposition filename has suspicious extension: {filename}",
                score_contribution=15.0,
                severity="medium",
            )
        return None

    def _check_path_typosquatting(
        self, path: str, brands: list[str],
    ) -> Finding | None:
        """Check URL path segments for brand typosquatting.

        Args:
            path: The URL path string.
            brands: List of brand FQDNs from config.

        Returns:
            Finding if a path segment is a typosquat of a known brand.
        """
        segments = [s.lower() for s in path.strip("/").split("/") if len(s) >= 4]

        for segment in segments:
            for brand_fqdn in brands:
                brand_name = tldextract.extract(brand_fqdn).domain.lower()
                if segment == brand_name:
                    continue
                dist = levenshtein_distance(segment, brand_name)
                if dist <= 2 and len(segment) >= 4:
                    return Finding(
                        description=(
                            f"Path segment '{segment}' is {dist} edit(s) away "
                            f"from brand '{brand_name}' (possible typosquatting)"
                        ),
                        score_contribution=30.0,
                        severity="high",
                    )
        return None

    def _download_and_hash(
        self, url: str, headers: dict, timeout: int, verify_ssl: bool,
    ) -> tuple[str, str, int]:
        """Download file content (up to 10MB) and compute SHA-1 + SHA-256.

        Args:
            url: The URL to download from.
            headers: Request headers.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            Tuple of (sha1_hex, sha256_hex, size_bytes).
        """
        try:
            resp = request_with_doh_fallback(
                "GET", url, headers=headers, timeout=timeout,
                verify=verify_ssl, stream=True,
            )
            resp.raise_for_status()

            sha1 = hashlib.sha1(usedforsecurity=False)  # file identity, not crypto
            sha256 = hashlib.sha256()
            total_bytes = 0

            for chunk in resp.iter_content(chunk_size=8192):
                sha1.update(chunk)
                sha256.update(chunk)
                total_bytes += len(chunk)
                if total_bytes >= _MAX_DOWNLOAD_BYTES:
                    break

            resp.close()
            return sha1.hexdigest(), sha256.hexdigest(), total_bytes

        except Exception as exc:
            logger.debug("Download failed for hashing %s: %s", url, exc)
            return "", "", 0

    def _check_virustotal_hash(
        self, sha256: str, api_key: str, timeout: int,
        file_info: FileDownloadInfo,
    ) -> Finding | None:
        """Look up file hash on VirusTotal.

        Args:
            sha256: The SHA-256 hash of the downloaded file.
            api_key: VirusTotal API key.
            timeout: Request timeout in seconds.
            file_info: FileDownloadInfo to update with VT results.

        Returns:
            Finding if VirusTotal flags the file.
        """
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": api_key},
                timeout=timeout,
            )

            file_info.vt_link = f"https://www.virustotal.com/gui/file/{sha256}"

            if resp.status_code == 404:
                return Finding(
                    description="File hash not found in VirusTotal database",
                    score_contribution=0.0,
                    severity="info",
                )

            if resp.status_code != 200:
                return None

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {},
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = scanned_engine_total(stats)

            file_info.vt_detections = malicious + suspicious
            file_info.vt_total_engines = total

            # Extract popular threat classification
            attrs = data.get("data", {}).get("attributes", {})
            ptc = attrs.get("popular_threat_classification", {})
            threat_label = ptc.get("popular_threat_name", [])
            if threat_label:
                file_info.popular_threat_label = threat_label[0].get("value", "")
            threat_cat = ptc.get("popular_threat_category", [])
            if threat_cat:
                file_info.threat_category = threat_cat[0].get("value", "")

            detection_count = malicious + suspicious

            if detection_count >= 3 or (total > 0 and detection_count / total > 0.05):
                return Finding(
                    description=(
                        f"VirusTotal: {malicious} malicious, {suspicious} suspicious "
                        f"detections out of {total} engines"
                    ),
                    score_contribution=50.0,
                    severity="critical",
                )

            if detection_count > 0:
                return Finding(
                    description=(
                        f"VirusTotal: low confidence — {detection_count} detection(s) "
                        f"out of {total} engines"
                    ),
                    score_contribution=5.0,
                    severity="low",
                )

            return Finding(
                description=f"VirusTotal: clean — 0 detections out of {total} engines",
                score_contribution=0.0,
                severity="info",
            )

        except requests.exceptions.RequestException as exc:
            logger.debug("VirusTotal hash lookup failed: %s", exc)
            return None
