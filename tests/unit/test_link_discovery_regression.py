from pathlib import Path


def test_link_discovery_candidate_text_casts_to_string() -> None:
    source = Path("src/socbox/analyzers/link_discovery.py").read_text(encoding="utf-8")
    assert "const rawText = (el.textContent ?? el.value ?? '');" in source
    assert "const text = String(rawText).trim();" in source
