"""Regression checks for SOC Box's independent project identity."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_SOURCES = (
    ROOT / "README.md",
    ROOT / "Phishing Snippet.md",
    ROOT / "src" / "socbox" / "web" / "templates" / "base.html",
    ROOT / "src" / "socbox" / "web" / "static" / "style.css",
)


def test_public_sources_do_not_reference_previous_employer_brand() -> None:
    forbidden = (
        "critical" + " start",
        "critical" + "start",
        "--" + "cs-",
        "cs-" + "mark",
        "cs-" + "favicon",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in PUBLIC_SOURCES).lower()

    for term in forbidden:
        assert term not in combined


def test_socbox_identity_assets_exist() -> None:
    assets = ROOT / "src" / "socbox" / "web" / "static" / "img"
    assert (assets / "socbox-mark.svg").is_file()
    assert (assets / "socbox-favicon.svg").is_file()
