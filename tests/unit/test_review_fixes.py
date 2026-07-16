"""Regression tests for the code-review fixes.

Guards the specific defects found in review so they can't silently return:
XSS-safe script embedding, DoH SSRF filtering, KQL injection escaping,
punycode homograph detection, the encoded-command false-positive tightening,
and evidence-scaled "Safe" confidence.
"""

from __future__ import annotations

import json

from socbox.analyzers.url_lexical import URLLexicalAnalyzer
from socbox.classification import classify
from socbox.dns_util import is_public_ip
from socbox.models import AnalyzerResult, AnalyzerStatus, RiskCategory
from socbox.scoring import _calculate_confidence
from socbox.web.app import _json_script_safe
from socbox.web.escalation import generate_kql_queries

_THRESHOLDS = {"safe": 25, "malicious": 60}


# --- XSS: script-safe JSON embedding --------------------------------------

def test_json_script_safe_neutralizes_script_breakout():
    payload = {"filename": "evil</script><img src=x onerror=alert(1)>.exe"}
    out = _json_script_safe(payload)
    assert "</script>" not in out
    assert "<" not in out and ">" not in out
    # Still valid JSON that round-trips to the original value.
    assert json.loads(out)["filename"] == payload["filename"]


def test_json_script_safe_preserves_spaces():
    assert _json_script_safe({"t": "a b c"}) == '{"t": "a b c"}'


# --- SSRF: DoH must never hand back a non-public address -------------------

def test_is_public_ip_classification():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("10.0.0.5") is False
    assert is_public_ip("169.254.169.254") is False  # cloud metadata
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("not-an-ip") is False


# --- KQL injection: attacker-controlled filename can't break out ----------

def test_kql_filename_is_escaped():
    queries = generate_kql_queries(
        domain="evil.com",
        url="http://evil.com",
        category="Malicious File Download",
        file_download={"sha256": "", "filename": 'x" or true //'},
        resolved_ip="1.2.3.4",
    )
    blob = "\n".join(q["query"] for q in queries)
    assert '\\"' in blob                 # the quote was escaped
    assert 'x" or true' not in blob      # and cannot break out of the literal


# --- Homograph: punycode/IDN labels are flagged ---------------------------

def test_punycode_hostname_flagged_as_homograph():
    analyzer = URLLexicalAnalyzer()
    assert analyzer._check_homograph("xn--pple-43d.com") is not None
    assert analyzer._check_homograph("www.example.com") is None


# --- Encoded command: long base64 alone is not enough ---------------------

def test_bare_base64_blob_is_not_encoded_command():
    ids = [c.id for c in classify(url="http://x", page_text="data " + "A" * 200)]
    assert "encoded_command" not in ids


def test_base64_with_shell_context_is_encoded_command():
    ids = [c.id for c in classify(url="http://x", page_text="powershell -enc " + "A" * 200)]
    assert "encoded_command" in ids


# --- Safe confidence scales with how much evidence was gathered ------------

def _completed(n: int) -> list[AnalyzerResult]:
    return [
        AnalyzerResult(
            analyzer_name=f"A{i}", status=AnalyzerStatus.COMPLETED,
            score=0.0, max_weight=10.0,
        )
        for i in range(n)
    ]


def test_safe_confidence_scales_with_completeness():
    full = _calculate_confidence(_completed(8), 5.0, 0.0, RiskCategory.SAFE, _THRESHOLDS)
    thin = _calculate_confidence(_completed(1), 5.0, 0.0, RiskCategory.SAFE, _THRESHOLDS)
    assert full == 100.0
    assert thin < full
