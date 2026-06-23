"""Unit tests for the download-intent cue heuristic.

The browser-download fallback waits the full poll budget only when the page
visibly advertises a pending download; a plain landing page is released early
so it never stalls the scan. These tests pin that gating logic.
"""

from iris.analyzers.download import DownloadAnalyzer


class _FakePage:
    """Minimal Playwright-page stub exposing only ``evaluate``."""

    def __init__(self, body_text: str = "", *, raises: bool = False) -> None:
        self._body_text = body_text
        self._raises = raises

    def evaluate(self, _script: str):  # noqa: D401 - stub
        if self._raises:
            raise RuntimeError("evaluate boom")
        # The real script lower-cases and slices; mirror that for fidelity.
        return self._body_text.lower()[:3000]


def test_download_intent_detected_on_cue():
    analyzer = DownloadAnalyzer()
    page = _FakePage("Please wait — your download will begin shortly.")
    assert analyzer._page_shows_download_intent(page) is True


def test_download_intent_absent_on_plain_landing_page():
    analyzer = DownloadAnalyzer()
    page = _FakePage("Sign in to your account to continue.")
    assert analyzer._page_shows_download_intent(page) is False


def test_download_intent_handles_empty_body():
    analyzer = DownloadAnalyzer()
    assert analyzer._page_shows_download_intent(_FakePage("")) is False


def test_download_intent_swallows_evaluate_errors():
    analyzer = DownloadAnalyzer()
    # A page whose evaluate raises must not crash the analyzer — treat as no cue.
    assert analyzer._page_shows_download_intent(_FakePage(raises=True)) is False
