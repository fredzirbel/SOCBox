"""Tests for threat classification (iris.classification.classify)."""

from __future__ import annotations

from iris.classification import classify
from iris.models import Finding


def _ids(classifications) -> set[str]:
    return {c.id for c in classifications}


def test_benign_page_has_no_classifications() -> None:
    result = classify(
        url="https://example.com",
        page_text="Welcome to Example. This domain is for use in examples.",
        scripts=[],
    )
    assert result == []


def test_clickfix_detected() -> None:
    text = (
        "Verify you are human. Press Windows + R, then Ctrl+V to paste and "
        "run this command in PowerShell to continue."
    )
    result = classify(url="https://bad.test", page_text=text)
    assert "clickfix" in _ids(result)
    cf = next(c for c in result if c.id == "clickfix")
    assert cf.attack_id == "T1204.004"
    assert cf.evidence  # captured what triggered it


def test_encoded_command_detected() -> None:
    text = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    result = classify(url="https://bad.test", page_text=text)
    assert "encoded_command" in _ids(result)


def test_credential_phishing_inferred_from_findings() -> None:
    findings = [
        Finding(
            description="Login form detected with password field",
            score_contribution=20, severity="high",
        ),
        Finding(
            description="Brand impersonation: Microsoft keywords on unrelated domain",
            score_contribution=15, severity="high",
        ),
    ]
    result = classify(url="https://bad.test", page_text="Sign in", findings=findings)
    assert "credential_phishing" in _ids(result)


def test_clipboard_hijack_detected_in_scripts() -> None:
    scripts = ["function steal(){ navigator.clipboard.writeText('malware'); }"]
    result = classify(url="https://bad.test", page_text="loading", scripts=scripts)
    assert "clipboard_hijack" in _ids(result)


def test_captcha_gated_detected_in_scripts() -> None:
    scripts = ["https://challenges.cloudflare.com/turnstile/v0/api.js"]
    result = classify(url="https://bad.test", page_text="just a moment", scripts=scripts)
    assert "captcha_gated" in _ids(result)


def test_multiple_classifications_coexist() -> None:
    text = "Press Win+R and paste this into PowerShell to verify you are human"
    scripts = ["navigator.clipboard.writeText('iex(...)')"]
    result = classify(url="https://bad.test", page_text=text, scripts=scripts)
    ids = _ids(result)
    assert "clickfix" in ids
    assert "clipboard_hijack" in ids
