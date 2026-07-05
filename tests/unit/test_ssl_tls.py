"""Unit tests for the SSL/TLS certificate checks.

These build synthetic certs in-memory (no network) and drive the analyzer's
check methods directly, guarding the regression where a CERT_NONE handshake
made ``getpeercert()`` return an empty dict and every cert check silently
no-opped on HTTPS sites.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from iris.analyzers.ssl_tls import SSLTLSAnalyzer


def _make_cert(
    *,
    cn: str = "example.com",
    issuer_org: str = "DigiCert Inc",
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    san: list[str] | None = None,
) -> x509.Certificate:
    """Build a self-signed cert with the requested attributes."""
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = not_before or (now - datetime.timedelta(days=365))
    not_after = not_after or (now + datetime.timedelta(days=365))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


_ANALYZER = SSLTLSAnalyzer()
_CFG = {"brands": ["microsoft.com", "paypal.com"]}


def test_expired_cert_is_flagged():
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = _make_cert(
        not_before=now - datetime.timedelta(days=400),
        not_after=now - datetime.timedelta(days=1),
    )
    finding = _ANALYZER._check_cert_expiry(cert)
    assert finding is not None and "expired" in finding.description.lower()


def test_valid_cert_not_flagged_as_expired():
    assert _ANALYZER._check_cert_expiry(_make_cert()) is None


def test_recently_issued_cert_is_flagged():
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = _make_cert(not_before=now - datetime.timedelta(days=2))
    finding = _ANALYZER._check_cert_age(cert)
    assert finding is not None and "recently" in finding.description.lower()


def test_old_cert_not_flagged_as_recent():
    assert _ANALYZER._check_cert_age(_make_cert()) is None


def test_hostname_mismatch_is_flagged():
    cert = _make_cert(cn="totally-different.example", san=["totally-different.example"])
    finding = _ANALYZER._check_subject_mismatch(cert, "victim-bank.com")
    assert finding is not None and "not valid for hostname" in finding.description


def test_matching_san_not_flagged():
    cert = _make_cert(cn="example.com", san=["example.com", "www.example.com"])
    assert _ANALYZER._check_subject_mismatch(cert, "www.example.com") is None


def test_wildcard_san_matches_one_label():
    cert = _make_cert(cn="*.example.com", san=["*.example.com"])
    assert _ANALYZER._check_subject_mismatch(cert, "login.example.com") is None
    # Wildcard must not match the bare apex or a deeper subdomain.
    assert _ANALYZER._check_subject_mismatch(cert, "example.com") is not None
    assert _ANALYZER._check_subject_mismatch(cert, "a.b.example.com") is not None


def test_ip_host_skips_mismatch_check():
    cert = _make_cert(cn="example.com", san=["example.com"])
    assert _ANALYZER._check_subject_mismatch(cert, "203.0.113.5") is None


def test_free_cert_on_brand_impersonating_domain_is_flagged():
    cert = _make_cert(issuer_org="Let's Encrypt")
    finding = _ANALYZER._check_cert_issuer(cert, "microsoft-login.com", _CFG)
    assert finding is not None and "microsoft" in finding.description.lower()


def test_free_cert_on_unrelated_domain_not_flagged():
    cert = _make_cert(issuer_org="Let's Encrypt")
    assert _ANALYZER._check_cert_issuer(cert, "my-personal-blog.com", _CFG) is None
