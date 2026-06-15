"""Tests for human-in-the-loop interactive CAPTCHA solving.

Covers detection, the manual-solve wait loop, the on-screen vs off-screen
launch behaviour, and that navigate_with_bypass only pauses for a manual
solve when interactive mode is enabled.
"""

from __future__ import annotations

import iris.browser as browser


class _FakePage:
    def __init__(self) -> None:
        self.url = "https://example.test"
        self.waited = 0

    def wait_for_timeout(self, ms):
        self.waited += ms


# ---------------------------------------------------------------------------
# detect_interactive_captcha
# ---------------------------------------------------------------------------

def test_detect_returns_provider_from_page() -> None:
    class _P:
        def evaluate(self, _js):
            return "hCaptcha"

    assert browser.detect_interactive_captcha(_P()) == "hCaptcha"


def test_detect_returns_empty_when_no_captcha() -> None:
    class _P:
        def evaluate(self, _js):
            return ""

    assert browser.detect_interactive_captcha(_P()) == ""


def test_detect_swallows_evaluate_errors() -> None:
    class _P:
        def evaluate(self, _js):
            raise RuntimeError("frame detached")

    assert browser.detect_interactive_captcha(_P()) == ""


# ---------------------------------------------------------------------------
# wait_for_manual_captcha_solve
# ---------------------------------------------------------------------------

def test_wait_returns_true_when_challenge_clears(monkeypatch) -> None:
    calls = {"n": 0}

    def _fake_detect(_page):
        calls["n"] += 1
        return "reCAPTCHA" if calls["n"] < 3 else ""

    monkeypatch.setattr(browser, "detect_interactive_captcha", _fake_detect)
    assert browser.wait_for_manual_captcha_solve(_FakePage(), "reCAPTCHA") is True


def test_wait_returns_false_on_timeout(monkeypatch) -> None:
    monkeypatch.setattr(browser, "detect_interactive_captcha", lambda _p: "reCAPTCHA")
    monkeypatch.setattr(browser, "_CAPTCHA_SOLVE_TIMEOUT_MS", 2000)
    monkeypatch.setattr(browser, "_CAPTCHA_POLL_MS", 1000)
    assert browser.wait_for_manual_captcha_solve(_FakePage(), "reCAPTCHA") is False


# ---------------------------------------------------------------------------
# launch_browser on-screen vs off-screen
# ---------------------------------------------------------------------------

class _FakeChromium:
    def __init__(self, fail_channel: bool = False) -> None:
        self.calls: list[dict] = []
        self.fail_channel = fail_channel

    def launch(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail_channel and kwargs.get("channel") == "chrome":
            raise RuntimeError("no system chrome")
        return object()


class _FakePW:
    def __init__(self, fail_channel: bool = False) -> None:
        self.chromium = _FakeChromium(fail_channel)


def _has_offscreen(args) -> bool:
    return any("--window-position=-9999" in a for a in args)


def test_default_launch_is_offscreen(monkeypatch) -> None:
    monkeypatch.setattr(browser, "build_chromium_args", lambda url: [])
    pw = _FakePW()
    browser.launch_browser(pw, "https://x.test")
    assert _has_offscreen(pw.chromium.calls[0]["args"])


def test_interactive_launch_is_onscreen(monkeypatch) -> None:
    monkeypatch.setattr(browser, "build_chromium_args", lambda url: [])
    pw = _FakePW()
    browser.launch_browser(pw, "https://x.test", interactive=True)
    assert not _has_offscreen(pw.chromium.calls[0]["args"])


def test_interactive_fallback_is_headed(monkeypatch) -> None:
    """When system Chrome is unavailable, the bundled fallback must be headed
    in interactive mode so the operator can see the challenge."""
    monkeypatch.setattr(browser, "build_chromium_args", lambda url: [])
    pw = _FakePW(fail_channel=True)
    browser.launch_browser(pw, "https://x.test", interactive=True)
    assert pw.chromium.calls[-1]["headless"] is False


def test_default_fallback_is_headless(monkeypatch) -> None:
    monkeypatch.setattr(browser, "build_chromium_args", lambda url: [])
    pw = _FakePW(fail_channel=True)
    browser.launch_browser(pw, "https://x.test")
    assert pw.chromium.calls[-1]["headless"] is True


# ---------------------------------------------------------------------------
# navigate_with_bypass interactive gating
# ---------------------------------------------------------------------------

def _patch_navigation(monkeypatch, captcha_provider: str):
    """Stub navigate_with_bypass's dependencies so only the interactive gate
    decides whether a manual solve is attempted."""
    monkeypatch.setattr(browser, "_simulate_human_behavior", lambda p: None)
    monkeypatch.setattr(browser, "_is_cloudflare_phishing_block", lambda p: False)
    monkeypatch.setattr(browser, "detect_interactive_captcha", lambda p: captcha_provider)

    solved = {"called": False}

    def _fake_solve(page, provider):
        solved["called"] = True
        return True

    monkeypatch.setattr(browser, "wait_for_manual_captcha_solve", _fake_solve)
    return solved


class _NavPage(_FakePage):
    def goto(self, *_a, **_k):
        class _Resp:
            status = 200

        return _Resp()


def test_navigate_pauses_for_solve_in_interactive_mode(monkeypatch) -> None:
    solved = _patch_navigation(monkeypatch, captcha_provider="hCaptcha")
    browser.set_interactive_mode(True)
    try:
        status = browser.navigate_with_bypass(_NavPage(), "https://x.test")
    finally:
        browser.set_interactive_mode(False)

    assert status == 200
    assert solved["called"] is True


def test_navigate_ignores_captcha_when_not_interactive(monkeypatch) -> None:
    solved = _patch_navigation(monkeypatch, captcha_provider="hCaptcha")
    browser.set_interactive_mode(False)

    status = browser.navigate_with_bypass(_NavPage(), "https://x.test")

    assert status == 200
    assert solved["called"] is False, "must not pause when interactive mode is off"
