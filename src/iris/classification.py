"""Threat classification for IRIS.

Assigns one or more *attack-technique* labels to a scanned URL, orthogonal to
the overall Safe/Uncertain/Malicious verdict produced by ``scoring``. A URL can
carry several classifications at once (e.g. ClickFix + encoded command). Each
maps to a MITRE ATT&CK technique so analysts can pivot.

Detection is rule-based and best-effort over the evidence already gathered
during a scan (rendered page text, inline scripts, analyzer findings, file
download metadata, redirect chain). It does not re-fetch anything.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from iris.models import ThreatClassification

if TYPE_CHECKING:
    from iris.models import FileDownloadInfo, Finding

# ---------------------------------------------------------------------------
# Pattern banks (all matched case-insensitively against lowercased text)
# ---------------------------------------------------------------------------

# ClickFix: fake "verify you're human" that instructs the victim to open the
# Run dialog and paste a command.
_RUN_DIALOG = ("win+r", "win + r", "windows + r", "windows key + r", "press windows", "⊞")
_PASTE = ("ctrl+v", "ctrl + v", "copy and paste", "paste it", "paste the", "right-click and paste")
_SHELL = ("powershell", "cmd.exe", "mshta", "run this command", "run dialog")
_VERIFY = (
    "verify you are human", "verify you are not a robot", "i am not a robot",
    "confirm you are human", "complete the verification", "press the key combination",
)

# Encoded / obfuscated command markers (strong — meaningful on their own).
_ENCODED_PATTERNS = (
    r"powershell(\.exe)?\s+-e(nc|ncodedcommand)?\b",
    r"-enc\b",
    r"frombase64string",
    r"\b(iex|invoke-expression)\b",
    r"\bmshta\b",
    r"certutil\s+(-|/)decode",
    r"-w(indowstyle)?\s+hidden",
)
# A long base64 blob is only an *encoded command* signal alongside the strong
# markers above (or a shell reference) — on its own it false-positives on inline
# data-URIs, source maps, JWTs, and other legitimate long base64.
_BASE64_BLOB = r"[A-Za-z0-9+/]{160,}={0,2}"

# Fake browser/software update lures.
_FAKE_UPDATE = (
    "update your browser", "browser is out of date", "your chrome is out of date",
    "chrome update", "update required", "manual update required", "update chrome",
)

# Tech-support scam markers (paired with a phone number).
_TECH_SUPPORT = (
    "virus detected", "your computer has been", "do not turn off your computer",
    "call microsoft", "windows defender alert", "your pc is blocked",
    "contact support immediately", "toll-free", "call this number", "security alert",
)
_PHONE = re.compile(r"(\+?\d[\d\-\s().]{8,}\d)")

# Clipboard hijack / pastejacking (inline-script signatures).
_CLIPBOARD = (
    "navigator.clipboard.writetext", "execcommand('copy')", 'execcommand("copy")',
    "clipboarddata.setdata", "document.execcommand('copy')",
)

# Crypto / wallet drainer signatures.
_DRAINER = (
    "eth_requestaccounts", "window.ethereum", "walletconnect", "web3modal",
    "connect wallet", "drainer", "seaport", "setapprovalforall",
)

# Real CAPTCHA-provider widgets (anti-analysis gating).
_CAPTCHA_HOSTS = ("challenges.cloudflare.com", "hcaptcha.com", "recaptcha")


def _hits(haystack: str, needles: tuple[str, ...]) -> list[str]:
    """Return the needles present in *haystack* (already lowercased)."""
    return [n for n in needles if n in haystack]


def classify(
    *,
    url: str = "",
    page_text: str = "",
    scripts: list[str] | None = None,
    findings: list[Finding] | None = None,
    file_download: FileDownloadInfo | None = None,
    redirect_chain: list[str] | None = None,
) -> list[ThreatClassification]:
    """Return the attack-technique classifications detected for a scan.

    Args:
        url: The scanned URL.
        page_text: Rendered/visible page text.
        scripts: Inline script bodies and external script ``src`` values.
        findings: Analyzer findings (used for credential-phishing inference).
        file_download: File-download metadata, if any.
        redirect_chain: Redirect hops, if any.

    Returns:
        A list of ThreatClassification, possibly empty.
    """
    text = (page_text or "").lower()
    script_blob = "\n".join(scripts or []).lower()
    haystack = f"{text}\n{script_blob}"
    finding_text = " ".join((f.description or "").lower() for f in (findings or []))
    has_download = bool(file_download and getattr(file_download, "detected", False))

    out: list[ThreatClassification] = []

    # --- ClickFix --------------------------------------------------------
    run = _hits(haystack, _RUN_DIALOG)
    paste = _hits(haystack, _PASTE)
    shell = _hits(haystack, _SHELL)
    verify = _hits(haystack, _VERIFY)
    if (run and (paste or shell)) or (verify and shell):
        out.append(ThreatClassification(
            id="clickfix",
            label="ClickFix",
            attack_id="T1204.004",
            attack_name="User Execution: Malicious Copy and Paste",
            severity="critical",
            evidence=(run + paste + shell + verify)[:6],
        ))

    # --- Encoded / obfuscated command ------------------------------------
    enc_evidence: list[str] = []
    for pat in _ENCODED_PATTERNS:
        m = re.search(pat, haystack, re.IGNORECASE)
        if m:
            frag = m.group(0)
            enc_evidence.append(frag[:40] + ("…" if len(frag) > 40 else ""))
    # Count a long base64 blob only when a shell/encoding context is present.
    if enc_evidence or shell:
        blob = re.search(_BASE64_BLOB, haystack)
        if blob:
            frag = blob.group(0)
            enc_evidence.append(frag[:40] + "…")
    if enc_evidence:
        out.append(ThreatClassification(
            id="encoded_command",
            label="Encoded / Obfuscated Command",
            attack_id="T1027",
            attack_name="Obfuscated Files or Information",
            severity="high",
            evidence=enc_evidence[:6],
        ))

    # --- Credential phishing (inferred from page-content findings) -------
    phishing_markers = ("login form", "password", "credential", "brand", "impersonat", "sign in")
    phishing_ev = [m for m in phishing_markers if m in finding_text]
    if phishing_ev:
        out.append(ThreatClassification(
            id="credential_phishing",
            label="Credential Phishing",
            attack_id="T1566.002",
            attack_name="Phishing: Spearphishing Link",
            severity="high",
            evidence=phishing_ev[:6],
        ))

    # --- Fake browser/software update ------------------------------------
    update_ev = _hits(text, _FAKE_UPDATE)
    if update_ev:
        out.append(ThreatClassification(
            id="fake_update",
            label="Fake Software Update",
            attack_id="T1189",
            attack_name="Drive-by Compromise",
            severity="high" if has_download else "medium",
            evidence=update_ev[:6],
        ))

    # --- Tech-support scam ------------------------------------------------
    ts_ev = _hits(text, _TECH_SUPPORT)
    if ts_ev and _PHONE.search(page_text or ""):
        out.append(ThreatClassification(
            id="tech_support_scam",
            label="Tech-Support Scam",
            attack_id="T1656",
            attack_name="Impersonation",
            severity="high",
            evidence=ts_ev[:6],
        ))

    # --- Clipboard hijack / pastejacking ---------------------------------
    clip_ev = _hits(script_blob, _CLIPBOARD)
    if clip_ev:
        out.append(ThreatClassification(
            id="clipboard_hijack",
            label="Clipboard Hijack (Pastejacking)",
            attack_id="T1059",
            attack_name="Command and Scripting Interpreter",
            severity="high",
            evidence=clip_ev[:6],
        ))

    # --- Crypto / wallet drainer -----------------------------------------
    drain_ev = _hits(haystack, _DRAINER)
    if drain_ev:
        out.append(ThreatClassification(
            id="crypto_drainer",
            label="Crypto / Wallet Drainer",
            attack_id="T1657",
            attack_name="Financial Theft",
            severity="high",
            evidence=drain_ev[:6],
        ))

    # --- Anti-analysis: CAPTCHA-gated ------------------------------------
    captcha_ev = _hits(script_blob, _CAPTCHA_HOSTS)
    if captcha_ev:
        out.append(ThreatClassification(
            id="captcha_gated",
            label="CAPTCHA-Gated (Anti-Analysis)",
            attack_id="T1497",
            attack_name="Virtualization/Sandbox Evasion",
            severity="info",
            evidence=captcha_ev[:6],
        ))

    return out
