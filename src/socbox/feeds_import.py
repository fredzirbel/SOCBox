"""Threat-intel feed importer for SOC Box.

Pulls recent malicious URLs from public threat-intel feeds via their official
APIs/feeds - never by scraping HTML - so an analyst can grab fresh, live
samples to scan without manual copy-paste (or getting IP-banned by abuse.ch).

Sources:
- **URLhaus** (abuse.ch) malware-distribution URLs. Requires a free Auth-Key
  (https://auth.abuse.ch) supplied via config ``api_keys.urlhaus`` or the
  ``URLHAUS_AUTH_KEY`` environment variable.
- **OpenPhish** community phishing feed (no key required).

Typical use::

    python -m socbox.feeds_import --source urlhaus --limit 20 --tag ClearFake
    python -m socbox.feeds_import --source openphish --limit 30 --output urls.txt

The printed URL list can be pasted into the web Bulk Scan box, or piped
elsewhere. URLs are printed verbatim (not defanged) so they can be fed
straight into a scanner; treat the output as live malicious infrastructure.
"""

from __future__ import annotations

import argparse
import os
import sys

import requests

from socbox.config import get_api_key, load_config

URLHAUS_RECENT_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

# URLhaus' recent endpoint caps `limit` at 1000.
_URLHAUS_MAX = 1000


def urlhaus_auth_key(config: dict | None = None) -> str:
    """Return the URLhaus Auth-Key from the environment or config.

    Args:
        config: Optional loaded SOC Box config dict.

    Returns:
        The Auth-Key string, or "" if not configured.
    """
    return os.environ.get("URLHAUS_AUTH_KEY", "") or get_api_key(config or {}, "urlhaus")


def fetch_urlhaus(
    auth_key: str,
    limit: int = 20,
    online_only: bool = True,
    tag: str | None = None,
    timeout: int = 20,
) -> list[dict]:
    """Fetch the most recent URLhaus URLs via the authenticated API.

    Args:
        auth_key: abuse.ch Auth-Key.
        limit: Maximum number of URLs to return.
        online_only: Keep only entries whose ``url_status`` is "online".
        tag: Optional case-insensitive tag filter (e.g. "ClearFake").
        timeout: HTTP timeout in seconds.

    Returns:
        List of dicts: {url, status, threat, tags}.

    Raises:
        ValueError: if no auth key is provided.
        RuntimeError: if the API returns a non-ok status.
    """
    if not auth_key:
        raise ValueError(
            "URLhaus Auth-Key required - set api_keys.urlhaus in config/local.yaml "
            "or the URLHAUS_AUTH_KEY env var (free key: https://auth.abuse.ch)."
        )

    # Request extra rows when filtering, since many recent entries are offline.
    fetch_n = min(_URLHAUS_MAX, limit * 5 if (online_only or tag) else limit)
    resp = requests.get(
        URLHAUS_RECENT_API,
        headers={"Auth-Key": auth_key},
        params={"limit": max(3, fetch_n)},
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus API error: {data.get('query_status')}")

    out: list[dict] = []
    for entry in data.get("urls", []):
        if online_only and entry.get("url_status") != "online":
            continue
        tags = entry.get("tags") or []
        if tag and tag.lower() not in [t.lower() for t in tags]:
            continue
        out.append({
            "url": entry.get("url", ""),
            "status": entry.get("url_status", "unknown"),
            "threat": entry.get("threat", ""),
            "tags": tags,
        })
        if len(out) >= limit:
            break
    return out


def fetch_openphish(limit: int = 20, timeout: int = 20) -> list[dict]:
    """Fetch recent phishing URLs from the OpenPhish community feed.

    Args:
        limit: Maximum number of URLs to return.
        timeout: HTTP timeout in seconds.

    Returns:
        List of dicts: {url, status, threat, tags}.
    """
    resp = requests.get(OPENPHISH_FEED, timeout=timeout)
    resp.raise_for_status()
    urls = [ln.strip() for ln in resp.text.splitlines() if ln.strip().startswith("http")]
    return [
        {"url": u, "status": "unknown", "threat": "phishing", "tags": []}
        for u in urls[:limit]
    ]


def main() -> None:
    """CLI entry point for the feed importer."""
    parser = argparse.ArgumentParser(
        prog="socbox-feeds",
        description="Pull recent malicious URLs from threat-intel feeds.",
    )
    parser.add_argument(
        "-s", "--source", choices=["urlhaus", "openphish"], default="urlhaus",
        help="Feed source (default: urlhaus)",
    )
    parser.add_argument(
        "-n", "--limit", type=int, default=20, help="Max URLs to return (default: 20)",
    )
    parser.add_argument(
        "-t", "--tag", default=None,
        help="URLhaus tag filter, e.g. ClearFake, Mozi (urlhaus only)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Include offline URLs too (URLhaus defaults to online-only)",
    )
    parser.add_argument(
        "-o", "--output", default=None, help="Write URLs (one per line) to this file",
    )
    parser.add_argument(
        "-c", "--config", default=None, help="Path to config YAML (for the URLhaus key)",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception:
        config = {}

    try:
        if args.source == "urlhaus":
            items = fetch_urlhaus(
                urlhaus_auth_key(config),
                limit=args.limit,
                online_only=not args.all,
                tag=args.tag,
            )
        else:
            items = fetch_openphish(limit=args.limit)
    except Exception as exc:
        print(f"Error fetching {args.source}: {exc}", file=sys.stderr)
        sys.exit(1)

    # Human-readable summary to stderr; clean URL list to stdout (pipe-friendly).
    print(
        f"# {len(items)} URL(s) from {args.source}"
        + (f" tagged '{args.tag}'" if args.tag else "")
        + (" (online only)" if not args.all and args.source == "urlhaus" else ""),
        file=sys.stderr,
    )
    for it in items:
        meta = " ".join(filter(None, [it["threat"], ",".join(it["tags"])]))
        print(f"#   [{it['status']}] {meta}", file=sys.stderr)
        print(it["url"])

    if args.output and items:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(it["url"] for it in items) + "\n")
        print(f"# wrote {len(items)} URL(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
