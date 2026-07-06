"""Unit tests for the standalone KQL generator."""

from __future__ import annotations

from iris.web.kql import (
    classify_indicators,
    claude_prompt,
    generate,
    generate_from_text,
)

_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def test_classify_mixed_defanged_blob():
    text = (
        "45[.]134[.]26[.]7, evil-login[.]com https://bad-portal.io/x "
        "sender@phish.tld " + _SHA256 + " " + _MD5
    )
    ind = classify_indicators(text)
    assert ind["ips"] == ["45.134.26.7"]
    assert "evil-login.com" in ind["domains"]
    assert "bad-portal.io" in ind["domains"]    # URL host folded into domains
    assert ind["urls"] == ["https://bad-portal.io/x"]
    assert ind["emails"] == ["sender@phish.tld"]
    assert ind["sha256"] == [_SHA256]
    assert ind["md5"] == [_MD5]


def test_classify_dedupes():
    ind = classify_indicators("8.8.8.8, 8.8.8.8, evil.com, EVIL.com")
    assert ind["ips"] == ["8.8.8.8"]
    assert ind["domains"] == ["evil.com"]  # lowercased + deduped


def test_generate_only_emits_present_types():
    queries = generate(classify_indicators("1.2.3.4"))
    tables = " ".join(q["query"] for q in queries)
    assert "DeviceNetworkEvents" in tables and "SigninLogs" in tables
    # No hash/email tables when only an IP was supplied.
    assert "DeviceFileEvents" not in tables and "EmailEvents" not in tables


def test_generate_hash_queries():
    queries = generate(classify_indicators(_SHA256))
    tables = "\n".join(q["query"] for q in queries)
    assert "DeviceFileEvents" in tables and "DeviceProcessEvents" in tables
    assert _SHA256 in tables


def test_kql_injection_escaped():
    # A domain containing a quote must not break out of the KQL string literal.
    queries = generate({"domains": ['evil.com" or true //'], "ips": [], "urls": [],
                         "sha256": [], "sha1": [], "md5": [], "emails": []})
    blob = "\n".join(q["query"] for q in queries)
    assert '\\"' in blob and 'evil.com" or true' not in blob


def test_claude_prompt_includes_indicators_and_goal():
    ind = classify_indicators("1.2.3.4 evil.com")
    prompt = claude_prompt(ind, "find beaconing")
    assert "1.2.3.4" in prompt and "evil.com" in prompt
    assert "find beaconing" in prompt
    assert "Advanced Hunting" in prompt


def test_generate_from_text_wraps_everything():
    out = generate_from_text("8.8.8.8", "test goal")
    assert set(out) == {"indicators", "queries", "claude_prompt"}
    assert out["indicators"]["ips"] == ["8.8.8.8"]
    assert out["queries"] and "test goal" in out["claude_prompt"]
