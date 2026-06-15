"""DNS resolution utilities for IRIS.

Provides fallback DNS resolution via public DNS-over-HTTPS (DoH) when the
system resolver blocks known-phishing domains.  Many ISP / router-level DNS
resolvers silently drop queries for domains on blocklists, causing
``ERR_NAME_NOT_RESOLVED`` in headless Chromium even though the domain is
still live.

The resolved IP can be fed to Chromium's ``--host-resolver-rules`` flag so
that Playwright can still reach the site for analysis.
"""

from __future__ import annotations

import logging
import socket
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


def resolve_hostname(url: str) -> str:
    """Resolve the hostname in *url* to an IPv4 address.

    Tries the system resolver first, then falls back to Cloudflare and
    Google public DoH endpoints.

    Args:
        url: A full URL (e.g. ``https://example.com/path``).

    Returns:
        The resolved IPv4 address, or an empty string on failure.
    """
    hostname = urlparse(url).hostname or ""
    if not hostname:
        return ""

    # 1. Try the system resolver
    try:
        ip = socket.gethostbyname(hostname)
        logger.debug("System DNS resolved %s -> %s", hostname, ip)
        return ip
    except (socket.gaierror, OSError):
        logger.debug("System DNS failed for %s, trying DoH fallback", hostname)

    # 2. Fallback: DNS-over-HTTPS (Cloudflare, then Google)
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
                    if ip:
                        logger.info("DoH (%s) resolved %s -> %s", server, hostname, ip)
                        return ip
        except Exception as exc:
            logger.debug("DoH %s failed for %s: %s", server, hostname, exc)

    logger.warning("All DNS resolution methods failed for %s", hostname)
    return ""


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
