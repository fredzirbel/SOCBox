"""Standalone KQL (Microsoft Advanced Hunting) generator for IRIS.

Turns a set of indicators (IP / domain / URL / file hash / email) into
ready-to-paste Microsoft Defender XDR + Sentinel Advanced Hunting queries via
deterministic templates — not tied to a scan, so analysts can pivot on any IOC.
It also assembles a copy-ready prompt for the analyst's own Claude seat when
they want a bespoke hunt beyond the templates (no third-party API call from
IRIS itself).

The per-scan escalation queries live in ``iris.web.escalation``; this shares its
``_kql_str`` escaper so attacker-controlled values (filenames, domains) can't
break out of a KQL string literal.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import tldextract

from iris.web.escalation import _kql_str

_LOOKBACK = "7d"

_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# The indicator buckets we classify into, in stable display order.
_TYPES = ("ips", "domains", "urls", "sha256", "sha1", "md5", "emails")


def _clean_token(tok: str) -> str:
    """Refang a token and strip wrapping punctuation."""
    t = (tok or "").strip().strip("<>()[]{}\"',;")
    t = (
        t.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
        .replace("[at]", "@").replace("(at)", "@")
        .replace("hxxps://", "https://").replace("hxxp://", "http://")
    )
    return t


def classify_indicators(text: str) -> dict[str, list[str]]:
    """Split a blob into typed, deduplicated indicator buckets.

    Args:
        text: Free-form text containing indicators (comma / whitespace / newline
            separated; defanged IOCs are refanged).

    Returns:
        Dict keyed by ``_TYPES`` with each list first-seen-ordered and unique.
    """
    buckets: dict[str, list[str]] = {t: [] for t in _TYPES}
    seen: dict[str, set[str]] = {t: set() for t in _TYPES}

    def add(kind: str, value: str) -> None:
        if value and value not in seen[kind]:
            seen[kind].add(value)
            buckets[kind].append(value)

    for raw in re.split(r"[\s,;]+", text or ""):
        tok = _clean_token(raw)
        if not tok:
            continue

        low = tok.lower()
        # Hashes first (unambiguous by length + hex).
        if _HEX_RE.match(tok):
            if len(tok) == 64:
                add("sha256", low)
                continue
            if len(tok) == 40:
                add("sha1", low)
                continue
            if len(tok) == 32:
                add("md5", low)
                continue

        # IP literal.
        try:
            ipaddress.ip_address(tok)
            add("ips", tok)
            continue
        except ValueError:
            pass

        # URL → keep the URL and also its registered domain.
        if "://" in tok or low.startswith(("http:", "https:")):
            add("urls", tok)
            ext = tldextract.extract(tok)
            if ext.suffix:
                add("domains", f"{ext.domain}.{ext.suffix}".lower())
            continue

        # Email / UPN.
        if _EMAIL_RE.match(tok):
            add("emails", low)
            continue

        # Bare domain (has a valid public suffix).
        ext = tldextract.extract(tok)
        if ext.domain and ext.suffix:
            add("domains", f"{ext.domain}.{ext.suffix}".lower())

    return buckets


def _kql_list(values: list[str]) -> str:
    """Render values as a quoted, escaped KQL ``in``/``has_any`` list body."""
    return ", ".join(f'"{_kql_str(v)}"' for v in values)


def _q(name: str, description: str, query: str, platform: str = "Defender XDR") -> dict[str, str]:
    return {"name": name, "description": description, "query": query, "platform": platform}


def generate(indicators: dict[str, list[str]]) -> list[dict[str, str]]:
    """Build Advanced Hunting queries for whichever indicator types are present."""
    ind = {t: list(indicators.get(t, [])) for t in _TYPES}
    out: list[dict[str, str]] = []

    if ind["ips"]:
        ips = _kql_list(ind["ips"])
        out.append(_q(
            "Endpoint connections to IP(s)",
            "Devices that connected to the indicator IP(s) in the last 7 days.",
            "DeviceNetworkEvents\n"
            f"| where Timestamp > ago({_LOOKBACK})\n"
            f"| where RemoteIP in~ ({ips})\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, "
            "RemoteIP, RemotePort, RemoteUrl, ActionType\n"
            "| sort by Timestamp desc",
        ))
        out.append(_q(
            "Sign-ins from IP(s)",
            "Entra ID sign-ins originating from the indicator IP(s).",
            "SigninLogs\n"
            f"| where TimeGenerated > ago({_LOOKBACK})\n"
            f"| where IPAddress in ({ips})\n"
            "| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, "
            "Location, ResultType, ResultDescription\n"
            "| sort by TimeGenerated desc",
            platform="Sentinel",
        ))

    # Domains + URL hosts share the web/email/network pivots.
    web = ind["domains"] + [u for u in ind["urls"] if u not in ind["domains"]]
    if web:
        vals = _kql_list(web)
        out.append(_q(
            "Email delivery of URL(s)/domain(s)",
            "Emails that delivered the indicator URL(s)/domain(s), with sender + recipient.",
            "EmailUrlInfo\n"
            f"| where Timestamp > ago({_LOOKBACK})\n"
            f"| where Url has_any ({vals})\n"
            f"| join kind=inner (EmailEvents | where Timestamp > ago({_LOOKBACK})) "
            "on NetworkMessageId\n"
            "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, "
            "Url, DeliveryAction, NetworkMessageId\n"
            "| sort by Timestamp desc",
        ))
        out.append(_q(
            "URL clicks (Safe Links)",
            "Users who clicked the indicator URL(s)/domain(s).",
            "UrlClickEvents\n"
            f"| where Timestamp > ago({_LOOKBACK})\n"
            f"| where Url has_any ({vals})\n"
            "| project Timestamp, AccountUpn, Url, ActionType, IPAddress\n"
            "| sort by Timestamp desc",
        ))
        out.append(_q(
            "Endpoint connections to domain(s)",
            "Devices that connected to the indicator domain(s)/URL host(s).",
            "DeviceNetworkEvents\n"
            f"| where Timestamp > ago({_LOOKBACK})\n"
            f"| where RemoteUrl has_any ({vals})\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, "
            "RemoteUrl, RemoteIP, ActionType\n"
            "| sort by Timestamp desc",
        ))

    # File hashes (any of the three) drive endpoint file/process hunts.
    hash_preds: list[str] = []
    if ind["sha256"]:
        hash_preds.append(f"SHA256 in~ ({_kql_list(ind['sha256'])})")
    if ind["sha1"]:
        hash_preds.append(f"SHA1 in~ ({_kql_list(ind['sha1'])})")
    if ind["md5"]:
        hash_preds.append(f"MD5 in~ ({_kql_list(ind['md5'])})")
    if hash_preds:
        pred = " or ".join(hash_preds)
        out.append(_q(
            "File on disk (by hash)",
            "Devices where the indicator file was created/downloaded.",
            "DeviceFileEvents\n"
            f"| where Timestamp > ago({_LOOKBACK})\n"
            f"| where {pred}\n"
            "| project Timestamp, DeviceName, InitiatingProcessAccountName, "
            "FileName, FolderPath, SHA256, ActionType\n"
            "| sort by Timestamp desc",
        ))
        out.append(_q(
            "File execution (by hash)",
            "Devices where the indicator file was executed.",
            "DeviceProcessEvents\n"
            f"| where Timestamp > ago({_LOOKBACK})\n"
            f"| where {pred}\n"
            "| project Timestamp, DeviceName, AccountName, FileName, "
            "ProcessCommandLine, SHA256, InitiatingProcessFileName\n"
            "| sort by Timestamp desc",
        ))

    if ind["emails"]:
        emails = _kql_list(ind["emails"])
        out.append(_q(
            "Email from sender(s)",
            "Messages from the indicator address(es), treating it as an external sender.",
            "EmailEvents\n"
            f"| where Timestamp > ago({_LOOKBACK})\n"
            f"| where SenderFromAddress in~ ({emails})\n"
            "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, "
            "DeliveryAction, ThreatTypes, NetworkMessageId\n"
            "| sort by Timestamp desc",
        ))
        out.append(_q(
            "Risky sign-ins for user(s)",
            "Failed/risky sign-ins, treating the address(es) as the affected UPN(s).",
            "SigninLogs\n"
            f"| where TimeGenerated > ago({_LOOKBACK})\n"
            f"| where UserPrincipalName in ({emails})\n"
            '| where ResultType != "0" or RiskLevelDuringSignIn in ("high", "medium")\n'
            "| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, "
            "Location, ResultType, RiskLevelDuringSignIn\n"
            "| sort by TimeGenerated desc",
            platform="Sentinel",
        ))

    return out


def claude_prompt(indicators: dict[str, list[str]], goal: str) -> str:
    """Assemble a copy-ready prompt for the analyst's own Claude seat.

    IRIS makes no API call — this is text the analyst pastes into their existing
    Claude Enterprise chat for a bespoke hunt beyond the deterministic templates.
    """
    lines = [
        "You are a senior SOC analyst writing Microsoft Defender XDR Advanced "
        "Hunting (KQL) queries. Note Sentinel table equivalents where they differ.",
        "",
        "Indicators:",
    ]
    labels = {
        "ips": "IPs", "domains": "Domains", "urls": "URLs",
        "sha256": "SHA256", "sha1": "SHA1", "md5": "MD5", "emails": "Emails",
    }
    any_ind = False
    for t in _TYPES:
        vals = indicators.get(t, [])
        if vals:
            any_ind = True
            lines.append(f"- {labels[t]}: {', '.join(vals)}")
    if not any_ind:
        lines.append("- (none supplied — infer suitable placeholders)")

    lines += [
        "",
        f"Hunt goal: {goal.strip() or 'Find any activity involving these indicators.'}",
        "",
        "Requirements:",
        "- Return each query in its own fenced ```kql code block with a one-line "
        "description above it.",
        "- Use the indicators above verbatim.",
        f"- Scope to the last {_LOOKBACK} unless the goal says otherwise.",
        "- Prefer DeviceNetworkEvents / DeviceProcessEvents / DeviceFileEvents / "
        "EmailEvents / EmailUrlInfo / UrlClickEvents / SigninLogs / "
        "IdentityLogonEvents as appropriate.",
    ]
    return "\n".join(lines)


def generate_from_text(text: str, goal: str = "") -> dict[str, Any]:
    """Convenience wrapper: classify a blob, then build queries + Claude prompt."""
    indicators = classify_indicators(text)
    return {
        "indicators": indicators,
        "queries": generate(indicators),
        "claude_prompt": claude_prompt(indicators, goal),
    }
