"""Data models for IRIS scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskCategory(Enum):
    """Overall risk classification for a scanned URL."""

    SAFE = "Safe"
    UNCERTAIN = "Uncertain"
    MALICIOUS = "Malicious"
    MALICIOUS_DOWNLOAD = "Malicious File Download"
    SUSPICIOUS_DOWNLOAD = "Suspicious File Download"


class AnalyzerStatus(Enum):
    """Status of an individual analyzer run."""

    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass
class Finding:
    """A single observation from an analyzer."""

    description: str
    score_contribution: float
    severity: str  # "info", "low", "medium", "high", "critical"


@dataclass
class AnalyzerResult:
    """Output from a single analysis layer."""

    analyzer_name: str
    status: AnalyzerStatus
    score: float  # 0-100 scale for this analyzer's dimension
    max_weight: float  # Max points this analyzer can contribute to overall score
    findings: list[Finding] = field(default_factory=list)
    error_message: str = ""


@dataclass
class FeedResult:
    """Output from a single threat feed check."""

    feed_name: str
    matched: bool
    details: str = ""
    raw_response: dict = field(default_factory=dict)
    display_order: int = 99


@dataclass
class FileDownloadInfo:
    """Metadata about a file download detected during scanning."""

    detected: bool
    filename: str = ""
    extension: str = ""
    content_type: str = ""
    size_bytes: int = 0
    sha1: str = ""
    sha256: str = ""
    vt_detections: int = 0
    vt_total_engines: int = 0
    vt_link: str = ""
    hosting_domain: str = ""
    is_abused_host: bool = False
    cloudflare_blocked: bool = False
    popular_threat_label: str = ""
    threat_category: str = ""


@dataclass
class ThreatClassification:
    """A detected attack technique, orthogonal to the overall risk verdict.

    A single URL may carry several classifications (e.g. ClickFix + encoded
    command). Each maps to a MITRE ATT&CK technique for analyst pivoting.
    """

    id: str  # stable slug, e.g. "clickfix"
    label: str  # human-readable, e.g. "ClickFix"
    attack_id: str  # MITRE ATT&CK technique id, e.g. "T1204.004"
    attack_name: str  # ATT&CK technique name, e.g. "Malicious Copy and Paste"
    severity: str  # "info", "low", "medium", "high", "critical"
    evidence: list[str] = field(default_factory=list)  # what triggered it


@dataclass
class DiscoveredLink:
    """A link/button found and followed during active link discovery."""

    element_text: str
    source_url: str
    destination_url: str
    has_credential_form: bool
    is_cross_domain: bool
    brand_detected: str = ""


@dataclass
class ScanReport:
    """Final aggregated scan report."""

    url: str
    overall_score: float
    risk_category: RiskCategory
    confidence: float
    analyzer_results: list[AnalyzerResult]
    feed_results: list[FeedResult]
    redirect_chain: list[str]
    recommendation: str
    timestamp: str
    screenshot_path: str = ""
    osint_links: list[dict] = field(default_factory=list)
    resolved_ip: str = ""
    discovered_links: list[DiscoveredLink] = field(default_factory=list)
    file_download: FileDownloadInfo | None = None
    # Keys: initial, initial_url, cta, cta_url, cta_text
    multi_screenshots: dict = field(default_factory=dict)
    threat_classifications: list[ThreatClassification] = field(default_factory=list)
