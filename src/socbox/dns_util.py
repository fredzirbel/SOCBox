"""DNS resolution utilities for SOC Box.

Provides fallback DNS resolution via public DNS-over-HTTPS (DoH) when the
system resolver blocks known-phishing domains.  Many ISP / router-level DNS
resolvers silently drop queries for domains on blocklists, causing
``ERR_NAME_NOT_RESOLVED`` in headless Chromium even though the domain is
still live.

The resolved IP can be fed to Chromium's ``--host-resolver-rules`` flag so
that Playwright can still reach the site for analysis.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


def is_public_ip(ip: str) -> bool:
    """Return True if *ip* is a routable public address.

    Used to keep the DoH fallback from ever handing back a private, loopback,
    link-local (incl. cloud metadata 169.254.169.254), multicast, reserved, or
    unspecified address — an SSRF bypass, since a public domain could carry an
    internal A record that the system resolver refuses but public DoH returns.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _resolve_via_doh(hostname: str) -> str:
    """Resolve *hostname* to an IPv4 address using public DoH endpoints.

    Queries Cloudflare then Google DNS-over-HTTPS, bypassing the system
    resolver entirely.  This is the fallback path for hosts the local
    resolver cannot (or refuses to) resolve.

    Args:
        hostname: A bare hostname (e.g. ``example.com``).

    Returns:
        The first A record found, or an empty string on failure.
    """
    if not hostname:
        return ""

    doh_servers = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]

    for server in doh_servers:
        try:
            resp = requests.get(
                server,
                params={"name": hostname, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            if resp.status_code != 200:
                continue

            data = resp.json()
            for answer in data.get("Answer", []):
                if answer.get("type") == 1:  # A record
                    ip = answer.get("data", "")
                    if not ip:
                        continue
                    # SSRF guard: never return an internal address from DoH.
                    if not is_public_ip(ip):
                        logger.warning(
                            "DoH (%s) returned non-public IP %s for %s — refusing",
                            server, ip, hostname,
                        )
                        return ""
                    logger.info("DoH (%s) resolved %s -> %s", server, hostname, ip)
                    return ip
        except Exception as exc:
            logger.debug("DoH %s failed for %s: %s", server, hostname, exc)

    logger.warning("All DNS resolution methods failed for %s", hostname)
    return ""


def resolve_host(hostname: str) -> str:
    """Resolve a bare *hostname* to an IPv4 address.

    Tries the system resolver first, then falls back to public DoH.

    Args:
        hostname: A bare hostname (e.g. ``example.com``).

    Returns:
        The resolved IPv4 address, or an empty string on failure.
    """
    if not hostname:
        return ""

    try:
        ip = socket.gethostbyname(hostname)
        logger.debug("System DNS resolved %s -> %s", hostname, ip)
        return ip
    except (socket.gaierror, OSError):
        logger.debug("System DNS failed for %s, trying DoH fallback", hostname)

    return _resolve_via_doh(hostname)


def resolve_hostname(url: str) -> str:
    """Resolve the hostname in *url* to an IPv4 address.

    Tries the system resolver first, then falls back to Cloudflare and
    Google public DoH endpoints.

    Args:
        url: A full URL (e.g. ``https://example.com/path``).

    Returns:
        The resolved IPv4 address, or an empty string on failure.
    """
    return resolve_host(urlparse(url).hostname or "")


# ---------------------------------------------------------------------------
# DoH-aware HTTP requests
# ---------------------------------------------------------------------------
#
# The browser reaches DoH-resolved hosts via Chromium's --host-resolver-rules
# (see build_chromium_args).  The requests-based analyzers (HTTP, download,
# threat feeds) have no such knob, so when the system resolver fails for the
# target host they error out — even though the host is reachable via DoH.
#
# request_with_doh_fallback() closes that gap: it issues a normal request, and
# on a DNS-class ConnectionError it resolves the host via DoH and retries with
# a thread-local getaddrinfo override.  Overriding getaddrinfo (rather than
# rewriting the URL to the IP) keeps SNI, certificate validation, the Host
# header, and redirect handling intact.
#
# The override is keyed per hostname in thread-local storage, so it is safe to
# use from the scanner's analyzer thread pool: concurrent threads never see
# each other's overrides, and hosts without an override resolve normally.

_local = threading.local()
_orig_getaddrinfo = socket.getaddrinfo
_patch_installed = False
_patch_lock = threading.Lock()

# Substrings that mark a name-resolution failure inside a ConnectionError chain.
_DNS_ERROR_MARKERS = (
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname",
    "getaddrinfo failed",
    "name resolution",
    "no address associated with hostname",
    "failed to resolve",
    "could not resolve host",
)


def _doh_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
    """getaddrinfo shim that honours the current thread's DoH overrides."""
    overrides = getattr(_local, "dns_overrides", None)
    if overrides:
        ip = overrides.get(host)
        if ip:
            return _orig_getaddrinfo(ip, *args, **kwargs)
    return _orig_getaddrinfo(host, *args, **kwargs)


def _ensure_getaddrinfo_patch() -> None:
    """Install the getaddrinfo shim once, lazily and thread-safely.

    When no thread has an active override the shim is a transparent
    passthrough, so installing it has no effect on normal resolution.
    """
    global _patch_installed
    if _patch_installed:
        return
    with _patch_lock:
        if not _patch_installed:
            socket.getaddrinfo = _doh_getaddrinfo
            _patch_installed = True


@contextmanager
def _dns_override(hostname: str, ip: str) -> Iterator[None]:
    """Temporarily map *hostname* to *ip* for getaddrinfo on this thread."""
    _ensure_getaddrinfo_patch()
    overrides = getattr(_local, "dns_overrides", None)
    if overrides is None:
        overrides = {}
        _local.dns_overrides = overrides

    had_prev = hostname in overrides
    prev = overrides.get(hostname)
    overrides[hostname] = ip
    try:
        yield
    finally:
        if had_prev:
            overrides[hostname] = prev
        else:
            overrides.pop(hostname, None)


def _is_dns_failure(exc: BaseException) -> bool:
    """Return True if *exc* (or a cause in its chain) is a DNS resolution failure."""
    seen: set[int] = set()
    node: BaseException | None = exc
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if isinstance(node, socket.gaierror):
            return True
        if any(marker in str(node).lower() for marker in _DNS_ERROR_MARKERS):
            return True
        node = node.__cause__ or node.__context__
    return False


def request_with_doh_fallback(
    method: str,
    url: str,
    *,
    session: requests.Session | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Make an HTTP request, falling back to DoH resolution on DNS failure.

    Issues ``method url`` normally.  If it fails with a name-resolution
    error, the target host is resolved via public DoH and the request is
    retried once with a thread-local getaddrinfo override so SNI, TLS
    verification, and redirects all behave as if the system resolver had
    worked.  Non-DNS errors (and DNS errors that DoH also cannot resolve)
    propagate unchanged to the caller.

    Args:
        method: HTTP method (``"GET"``, ``"HEAD"``, ...).
        url: The URL to request.
        session: Optional pre-configured ``requests.Session`` (e.g. with a
            custom ``max_redirects``); a one-off request is used otherwise.
        **kwargs: Passed through to ``requests`` (headers, timeout, etc.).

    Returns:
        The ``requests.Response``.

    Raises:
        requests.exceptions.RequestException: If the request fails for a
            non-DNS reason, or DoH cannot resolve the host either.
    """
    requester = session.request if session is not None else requests.request

    try:
        return requester(method, url, **kwargs)
    except requests.exceptions.ConnectionError as exc:
        if not _is_dns_failure(exc):
            raise

        hostname = urlparse(url).hostname or ""
        ip = _resolve_via_doh(hostname) if hostname else ""
        if not ip:
            raise

        logger.info(
            "System DNS failed for %s; retrying request via DoH IP %s", hostname, ip
        )
        with _dns_override(hostname, ip):
            return requester(method, url, **kwargs)


def compute_host_resolver_rule(url: str) -> str:
    """Return the Chromium ``--host-resolver-rules`` value needed for *url*.

    Chromium can only learn DNS overrides at launch time, so callers that
    cache a browser need to know the exact rule a URL requires in order to
    decide whether a cached browser is still valid for it.

    Returns a ``MAP <host> <ip>`` rule string when the system resolver
    cannot resolve the host but DoH can; otherwise an empty string, meaning
    no override is needed (the system resolver handles it).

    Args:
        url: The URL that will be navigated to.

    Returns:
        A ``MAP <host> <ip>`` rule string, or ``""`` when no override is needed.
    """
    hostname = urlparse(url).hostname or ""
    if not hostname:
        return ""

    try:
        socket.gethostbyname(hostname)
        return ""  # System DNS works — no override required.
    except (socket.gaierror, OSError):
        ip = resolve_hostname(url)
        if ip:
            return f"MAP {hostname} {ip}"
        return ""


def build_chromium_args(url: str) -> list[str]:
    """Build Chromium launch arguments, with DNS override if needed.

    Always includes anti-fingerprinting flags.  If the system DNS cannot
    resolve the hostname, resolves via DoH and adds a
    ``--host-resolver-rules`` mapping so Chromium can reach the site.

    Args:
        url: The URL that will be navigated to.

    Returns:
        List of Chromium CLI argument strings.
    """
    args = [
        "--disable-blink-features=AutomationControlled",
    ]

    rule = compute_host_resolver_rule(url)
    if rule:
        args.append(f"--host-resolver-rules={rule}")
        logger.info("Added host-resolver-rule: %s", rule)

    return args
