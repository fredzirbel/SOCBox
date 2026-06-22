"""KQL hunting-query generator for IRIS.

Produces ready-to-paste KQL hunting queries (Microsoft Defender XDR advanced
hunting + Azure Sentinel) tailored to what a scan found:

- Any URL → URL-click and email-delivery queries on the domain.
- Phishing / malicious URL → an anomalous sign-in query (UPN-driven).
- Malicious / suspicious file download → endpoint queries pivoting on the
  file's SHA-256 / filename and the hosting domain/IP, plus the delivery queries.

The escalation write-up itself is produced by the SOC's separate investigative
agent, so IRIS no longer generates it.
"""

from __future__ import annotations

from typing import Any

# Risk categories (RiskCategory.value) that indicate a file download.
_DOWNLOAD_CATEGORIES = {"Malicious File Download", "Suspicious File Download"}

# Placeholder the UI live-substitutes with the analyst's UPN.
UPN_PLACEHOLDER = "<UPN>"


def _kql(name: str, description: str, query: str) -> dict[str, str]:
    """Build a KQL query dict in the shape the UI expects."""
    return {"name": name, "description": description, "query": query}


def _url_delivery_queries(domain: str) -> list[dict[str, str]]:
    """URL-click + email-delivery queries — relevant to any scanned URL."""
    return [
        _kql(
            "URL Clicks",
            f"Users who clicked URLs containing '{domain}' in the last 7 days "
            "(Defender for Office Safe Links).",
            "UrlClickEvents\n"
            "| where Timestamp > ago(7d)\n"
            f'| where Url contains "{domain}"\n'
            "| summarize ClickCount = count() by AccountUpn, Url, ActionType\n"
            "| sort by ClickCount desc",
        ),
        _kql(
            "Email Delivery",
            f"Emails that delivered URLs containing '{domain}' in the last 7 "
            "days, with sender + recipient scope.",
            "EmailUrlInfo\n"
            "| where Timestamp > ago(7d)\n"
            f'| where Url contains "{domain}"\n'
            "| join kind=inner (EmailEvents | where Timestamp > ago(7d)) "
            "on NetworkMessageId\n"
            "| summarize EmailCount = count() by "
            "SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId\n"
            "| sort by EmailCount desc",
        ),
    ]


def _signin_query() -> dict[str, str]:
    """Anomalous / failed sign-in hunt for the affected user (UPN-driven)."""
    return _kql(
        "Anomalous Sign-in",
        f"Failed and risky sign-ins for the affected user in the last 7 days. "
        f"{UPN_PLACEHOLDER} is auto-filled from the UPN field above.",
        "SigninLogs\n"
        "| where TimeGenerated > ago(7d)\n"
        f'| where UserPrincipalName == "{UPN_PLACEHOLDER}"\n'
        '| where ResultType != "0" or RiskLevelDuringSignIn in ("high", "medium")\n'
        "| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, "
        "Location, ResultType, ResultDescription, RiskLevelDuringSignIn\n"
        "| sort by TimeGenerated desc",
    )


def _download_queries(
    file_download: dict[str, Any] | None,
    domain: str,
    resolved_ip: str,
) -> list[dict[str, str]]:
    """Endpoint (Defender XDR Device*) queries for a downloaded file.

    Each query is only emitted when the pivot it needs is available, so a
    Cloudflare-blocked download with no captured file still gets the
    domain/IP network query.
    """
    fd = file_download or {}
    sha256 = (fd.get("sha256") or "").strip()
    filename = (fd.get("filename") or "").strip()

    # Build the "SHA256 == ... or FileName =~ ..." predicate from whatever we have.
    file_preds: list[str] = []
    if sha256:
        file_preds.append(f'SHA256 == "{sha256}"')
    if filename:
        file_preds.append(f'FileName =~ "{filename}"')
    file_filter = " or ".join(file_preds)

    queries: list[dict[str, str]] = []

    if file_filter:
        queries.append(_kql(
            "File on Disk",
            "Devices where this file was created/downloaded in the last 7 days.",
            "DeviceFileEvents\n"
            "| where Timestamp > ago(7d)\n"
            f"| where {file_filter}\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, "
            "FileName, FolderPath, SHA256, ActionType\n"
            "| sort by Timestamp desc",
        ))
        queries.append(_kql(
            "File Execution",
            "Devices where this file was executed in the last 7 days.",
            "DeviceProcessEvents\n"
            "| where Timestamp > ago(7d)\n"
            f"| where {file_filter}\n"
            "| project Timestamp, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, SHA256, InitiatingProcessFileName\n"
            "| sort by Timestamp desc",
        ))

    # Network query keys off the hosting domain / resolved IP.
    net_preds: list[str] = []
    if domain:
        net_preds.append(f'RemoteUrl has "{domain}"')
    if resolved_ip:
        net_preds.append(f'RemoteIP == "{resolved_ip}"')
    if net_preds:
        queries.append(_kql(
            "Host Connections",
            "Devices that connected to the file's hosting domain/IP in the "
            "last 7 days (download source / possible C2).",
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(7d)\n"
            f"| where {' or '.join(net_preds)}\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, "
            "RemoteUrl, RemoteIP, RemotePort, ActionType\n"
            "| sort by Timestamp desc",
        ))

    return queries


def generate_kql_queries(
    domain: str,
    url: str,
    *,
    category: str = "",
    file_download: dict[str, Any] | None = None,
    resolved_ip: str = "",
) -> list[dict[str, str]]:
    """Generate verdict- and artifact-aware KQL hunting queries.

    Args:
        domain: The domain from the scanned URL (e.g. ``"evil.com"``).
        url: The full scanned URL (kept for future per-URL queries).
        category: The scan verdict (``RiskCategory.value``) — selects the
            query set (download verdicts get endpoint queries instead of a
            sign-in query).
        file_download: File-download metadata (``sha256`` / ``filename``) used
            to pivot the endpoint queries; ``None`` for non-download scans.
        resolved_ip: The resolved host IP, used by the network query.

    Returns:
        A list of dicts with keys ``name``, ``description``, and ``query``.
    """
    is_download = category in _DOWNLOAD_CATEGORIES

    # URL-click + email-delivery queries apply to every scanned URL (and to
    # downloads too — the file arrived via a link/email).
    queries = _url_delivery_queries(domain)

    if is_download:
        queries.extend(_download_queries(file_download, domain, resolved_ip))
    else:
        queries.append(_signin_query())

    return queries
