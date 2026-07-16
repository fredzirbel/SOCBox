"""WHOIS and DNS analysis for phishing detection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import tldextract

from socbox.analyzers.base import BaseAnalyzer
from socbox.models import AnalyzerResult, AnalyzerStatus, Finding


class WhoisDNSAnalyzer(BaseAnalyzer):
    """Analyze WHOIS records and DNS configuration for phishing indicators.

    Checks domain age, registrar reputation, and DNS record anomalies.
    """

    name = "WHOIS/DNS Inspection"
    weight = 15.0

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Run WHOIS and DNS checks against the URL's domain.

        Args:
            url: The URL to analyze.
            config: The loaded configuration dictionary.

        Returns:
            AnalyzerResult with WHOIS/DNS findings.
        """
        findings: list[Finding] = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else hostname

        # WHOIS check
        whois_findings = self._check_whois(domain)
        findings.extend(whois_findings)

        # DNS checks
        dns_findings = self._check_dns(domain, hostname)
        findings.extend(dns_findings)

        score = min(100.0, sum(f.score_contribution for f in findings))

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    def _check_whois(self, domain: str) -> list[Finding]:
        """Query WHOIS and check domain age and registrar.

        Args:
            domain: The registered domain to look up.

        Returns:
            List of findings from WHOIS data.
        """
        findings: list[Finding] = []

        try:
            import whois

            w = whois.whois(domain)
        except Exception:
            findings.append(
                Finding(
                    description="WHOIS lookup failed (domain may be unregistered or protected)",
                    score_contribution=10.0,
                    severity="low",
                )
            )
            return findings

        # Check domain age
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            try:
                if not creation_date.tzinfo:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation_date).days

                if age_days < 30:
                    findings.append(
                        Finding(
                            description=f"Domain registered very recently ({age_days} days ago)",
                            score_contribution=30.0,
                            severity="high",
                        )
                    )
                elif age_days < 90:
                    findings.append(
                        Finding(
                            description=f"Domain registered recently ({age_days} days ago)",
                            score_contribution=15.0,
                            severity="medium",
                        )
                    )
            except (TypeError, AttributeError):
                pass

        # Check privacy protection (common in phishing domains)
        registrar = str(w.registrar or "").lower()
        if any(kw in registrar for kw in ["privacy", "proxy", "protect", "redacted"]):
            findings.append(
                Finding(
                    description=f"Domain uses privacy/proxy registration: {w.registrar}",
                    score_contribution=5.0,
                    severity="info",
                )
            )

        return findings

    def _check_dns(self, domain: str, hostname: str) -> list[Finding]:
        """Check DNS records for anomalies.

        Args:
            domain: The registered domain.
            hostname: The full hostname from the URL.

        Returns:
            List of findings from DNS analysis.
        """
        findings: list[Finding] = []

        # Check if domain resolves at all
        try:
            dns.resolver.resolve(hostname, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            findings.append(
                Finding(
                    description="Domain does not resolve (NXDOMAIN or no A record)",
                    score_contribution=20.0,
                    severity="high",
                )
            )
            return findings
        except Exception:
            findings.append(
                Finding(
                    description="DNS resolution failed",
                    score_contribution=5.0,
                    severity="low",
                )
            )
            return findings

        # Check for no MX records (legitimate sites usually have email)
        try:
            dns.resolver.resolve(domain, "MX")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append(
                Finding(
                    description="Domain has no MX records (no email infrastructure)",
                    score_contribution=10.0,
                    severity="low",
                )
            )
        except Exception:
            pass

        # Reverse DNS (PTR) checking was intentionally removed: it relied on the
        # OS resolver (ignoring the configured DNS servers), routinely stalled
        # several seconds before timing out, and produced near-zero signal —
        # modern phishing is overwhelmingly CDN-fronted, where PTR records are
        # absent or shared and a "mismatch" means nothing.

        return findings
