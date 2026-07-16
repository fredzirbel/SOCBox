"""SSL/TLS certificate analysis for phishing detection."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import tldextract
from cryptography import x509
from cryptography.x509.oid import NameOID

from socbox.analyzers.base import BaseAnalyzer
from socbox.models import AnalyzerResult, AnalyzerStatus, Finding

# Certificate issuers commonly used by free/automated CAs
FREE_CERT_ISSUERS = [
    "let's encrypt",
    "letsencrypt",
    "zerossl",
    "buypass",
    "ssl.com free",
]


class SSLTLSAnalyzer(BaseAnalyzer):
    """Analyze the SSL/TLS certificate for phishing indicators.

    Checks certificate issuer, age, subject/domain mismatch,
    and free cert usage on brand-impersonating domains.
    """

    name = "SSL/TLS Certificate"
    weight = 15.0

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Retrieve and inspect the SSL certificate for the URL's host.

        Args:
            url: The URL to analyze.
            config: The loaded configuration dictionary.

        Returns:
            AnalyzerResult with SSL/TLS findings.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if parsed.scheme == "http":
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.COMPLETED,
                score=20.0,
                max_weight=self.weight,
                findings=[
                    Finding(
                        description="Site uses HTTP (no TLS encryption)",
                        score_contribution=20.0,
                        severity="medium",
                    )
                ],
            )

        cert = self._get_certificate(hostname, port, config)
        if cert is None:
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.COMPLETED,
                score=25.0,
                max_weight=self.weight,
                findings=[
                    Finding(
                        description="Could not retrieve SSL certificate",
                        score_contribution=25.0,
                        severity="medium",
                    )
                ],
            )

        findings: list[Finding] = []

        checks = [
            self._check_cert_issuer(cert, hostname, config),
            self._check_cert_age(cert),
            self._check_subject_mismatch(cert, hostname),
            self._check_cert_expiry(cert),
        ]

        for result in checks:
            if result is not None:
                findings.append(result)

        score = min(100.0, sum(f.score_contribution for f in findings))

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    def _get_certificate(
        self, hostname: str, port: int, config: dict[str, Any]
    ) -> x509.Certificate | None:
        """Retrieve and parse the server's leaf certificate.

        The connection is made with verification disabled (this tool inspects
        malicious infrastructure whose certs routinely fail validation). The
        cert is fetched in DER form and parsed with ``cryptography``: under
        ``CERT_NONE`` the stdlib ``getpeercert(binary_form=False)`` returns an
        empty dict, so the DER path is the only way to actually read issuer,
        validity dates, and SANs.

        Args:
            hostname: The hostname to connect to.
            port: The port number.
            config: Configuration dictionary.

        Returns:
            The parsed leaf certificate, or None if retrieval/parse failed.
        """
        timeout = config.get("requests", {}).get("timeout", 10)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
        except Exception:
            return None

        if not der:
            return None
        try:
            return x509.load_der_x509_certificate(der)
        except Exception:
            return None

    @staticmethod
    def _issuer_org(cert: x509.Certificate) -> str:
        """Return the certificate issuer's organization name, lowercased."""
        try:
            attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if attrs:
                return str(attrs[0].value).lower()
        except Exception:
            pass
        return ""

    @staticmethod
    def _cert_dns_names(cert: x509.Certificate) -> list[str]:
        """Return the DNS names the cert is valid for (SAN dNSNames + CN)."""
        names: list[str] = []
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            names.extend(san.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn:
                names.append(str(cn[0].value))
        except Exception:
            pass
        return [n.lower().rstrip(".") for n in names if n]

    @staticmethod
    def _not_before(cert: x509.Certificate) -> datetime:
        """Return the cert's notBefore as a timezone-aware UTC datetime."""
        dt = getattr(cert, "not_valid_before_utc", None)
        if dt is None:  # cryptography < 42
            dt = cert.not_valid_before.replace(tzinfo=timezone.utc)
        return dt

    @staticmethod
    def _not_after(cert: x509.Certificate) -> datetime:
        """Return the cert's notAfter as a timezone-aware UTC datetime."""
        dt = getattr(cert, "not_valid_after_utc", None)
        if dt is None:  # cryptography < 42
            dt = cert.not_valid_after.replace(tzinfo=timezone.utc)
        return dt

    def _check_cert_issuer(
        self, cert: x509.Certificate, hostname: str, config: dict[str, Any]
    ) -> Finding | None:
        """Check if a free cert is being used on a brand-impersonating domain.

        Args:
            cert: The parsed leaf certificate.
            hostname: The hostname being checked.
            config: Configuration with brand list.

        Returns:
            Finding if free cert + brand impersonation detected.
        """
        issuer_str = self._issuer_org(cert)

        is_free_cert = any(free in issuer_str for free in FREE_CERT_ISSUERS)
        if not is_free_cert:
            return None

        # Check if domain looks like it's impersonating a brand
        extracted = tldextract.extract(hostname)
        domain = extracted.domain.lower()
        brands = config.get("brands", [])

        for brand_fqdn in brands:
            brand_name = tldextract.extract(brand_fqdn).domain.lower()
            if brand_name in domain and domain != brand_name:
                return Finding(
                    description=(
                        f"Free certificate (issued by '{issuer_str}') on domain "
                        f"that contains brand name '{brand_name}'"
                    ),
                    score_contribution=25.0,
                    severity="high",
                )

        return None

    def _check_cert_age(self, cert: x509.Certificate) -> Finding | None:
        """Check if the certificate was issued very recently.

        Args:
            cert: The parsed leaf certificate.

        Returns:
            Finding if cert was issued less than 7 days ago.
        """
        try:
            issued_date = self._not_before(cert)
            age_days = (datetime.now(timezone.utc) - issued_date).days
        except Exception:
            return None

        if age_days < 7:
            return Finding(
                description=f"Certificate issued very recently ({age_days} days ago)",
                score_contribution=15.0,
                severity="medium",
            )
        return None

    def _check_subject_mismatch(
        self, cert: x509.Certificate, hostname: str
    ) -> Finding | None:
        """Check if the certificate is not valid for the requested hostname.

        Compares the hostname against the cert's SAN dNSNames (and CN),
        honouring single-label wildcards. Skipped for IP-literal hosts, where
        DNS-name matching does not apply.

        Args:
            cert: The parsed leaf certificate.
            hostname: The hostname to verify against.

        Returns:
            Finding if the hostname matches none of the cert's names.
        """
        try:
            ipaddress.ip_address(hostname)
            return None  # IP host — SAN dNSName matching is not meaningful
        except ValueError:
            pass

        names = self._cert_dns_names(cert)
        if not names:
            return None  # nothing to compare against

        if self._hostname_matches(hostname.lower().rstrip("."), names):
            return None

        return Finding(
            description=(
                f"Certificate is not valid for hostname '{hostname}' "
                f"(covers: {', '.join(names[:3])})"
            ),
            score_contribution=30.0,
            severity="high",
        )

    @staticmethod
    def _hostname_matches(host: str, names: list[str]) -> bool:
        """Return True if *host* matches any cert name (single-label wildcards)."""
        for name in names:
            if name == host:
                return True
            if name.startswith("*."):
                # "*.example.com" matches one label: a.example.com, not example.com
                suffix = name[1:]  # ".example.com"
                if host.endswith(suffix) and host.count(".") == name.count("."):
                    return True
        return False

    def _check_cert_expiry(self, cert: x509.Certificate) -> Finding | None:
        """Check if the certificate is expired.

        Args:
            cert: The parsed leaf certificate.

        Returns:
            Finding if the cert is expired.
        """
        try:
            expiry_date = self._not_after(cert)
        except Exception:
            return None

        if expiry_date < datetime.now(timezone.utc):
            return Finding(
                description="SSL certificate is expired",
                score_contribution=25.0,
                severity="high",
            )
        return None
