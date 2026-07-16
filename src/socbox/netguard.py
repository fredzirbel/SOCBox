"""SSRF guard for SOC Box.

SOC Box fetches user-supplied URLs server-side (the requests-based analyzers and a
real browser). Without a guard, that turns the scanner into a server-side
request oracle: an attacker could point it at internal services or the cloud
metadata endpoint (169.254.169.254). ``target_block_reason`` resolves the
target host and refuses anything that lands on a non-public address.

The check runs at scan submission, before any analyzer or the browser starts,
so it covers every fetch path at once.

Residual risk: DNS rebinding (the host could resolve to a public IP at check
time and an internal one at connect time). The durable fix is per-connection IP
pinning / an egress proxy (roadmap); this guard closes the common case.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from socbox.dns_util import resolve_host

_ALLOWED_SCHEMES = ("http", "https")


def _ip_is_non_public(ip_str: str) -> bool:
    """Return True if *ip_str* is private / loopback / link-local / etc."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local      # incl. cloud metadata 169.254.169.254
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def target_block_reason(
    url: str,
    *,
    block_private: bool = True,
    allowlist: object = (),
) -> str | None:
    """Return a reason to block scanning *url*, or ``None`` if it is safe.

    Args:
        url: The user-supplied URL to scan.
        block_private: Master switch; when False the guard is disabled
            (air-gapped / lab use only).
        allowlist: Hostnames exempted from the private-address block.

    Returns:
        A human-readable block reason, or ``None`` when the target is allowed.
    """
    parsed = urlparse(url if "://" in (url or "") else f"https://{url or ''}")
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        return f"unsupported URL scheme '{scheme}' (only http/https allowed)"

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return "URL has no host"

    if not block_private:
        return None

    allow = {str(h).strip().lower() for h in (allowlist or [])}
    if hostname.lower() in allow:
        return None

    # IP-literal host (incl. IPv6 like [::1]) → check directly; otherwise resolve.
    try:
        ipaddress.ip_address(hostname)
        candidate_ips = [hostname]
    except ValueError:
        ip = resolve_host(hostname)
        if not ip:
            # Unresolvable → the scan will simply fail to connect; no SSRF path.
            return None
        candidate_ips = [ip]

    for ip_str in candidate_ips:
        if _ip_is_non_public(ip_str):
            return f"target resolves to a non-public address ({ip_str})"
    return None
