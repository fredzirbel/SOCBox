"""Orchestration tests for the web noVNC CAPTCHA takeover.

These cover the handoff logic that ties the headless scan to the headed solve —
the parts unit-testable without an X display or a real browser:

  * ``remote_takeover_solve`` — captures the scan's session, runs the headed
    job, and on success stashes the clearance for the scan to replay.
  * ``navigate_with_bypass`` (human-present branch) — on a detected gate, hands
    off to the takeover and replays the clearance past the gate, but only when
    the takeover actually succeeds.
  * ``_replay_clearance_and_reload`` — injects the solved cookies and reloads.

The headed solve itself (``_takeover_job``) and the Xvfb/x11vnc/websockify noVNC
plumbing are container-bound and verified live, not here.
"""

from __future__ import annotations

import iris.browser as browser

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _Ctx:
    """A context that reports a fixed storage_state and records cookie injects."""

    def __init__(self, state: dict | None = None) -> None:
        self._state = state or {"cookies": []}
        self.added: list | None = None

    def storage_state(self) -> dict:
        return self._state

    def add_cookies(self, cookies) -> None:
        self.added = cookies


class _Page:
    def __init__(self, state: dict | None = None) -> None:
        self.url = "https://x.test"
        self.context = _Ctx(state)
        self.goto_args: tuple | None = None
        self.waited = 0

    def wait_for_timeout(self, ms) -> None:
        self.waited += ms

    def goto(self, url, **kwargs):
        self.goto_args = (url, kwargs)

        class _Resp:
            status = 200

        return _Resp()


# ---------------------------------------------------------------------------
# remote_takeover_solve
# ---------------------------------------------------------------------------

def test_remote_takeover_solve_stashes_clearance_on_success(monkeypatch) -> None:
    """A solved takeover returns True and stashes the clearance, and the scan's
    own session is what gets handed to the headed job."""
    browser.reset_solved_state()
    clearance = {"cookies": [{"name": "cf_clearance", "value": "abc"}]}
    handed: dict[str, object] = {}

    def _fake_job(url, provider, session_state, timeout_ms):
        handed["session_state"] = session_state
        handed["url"] = url
        return clearance

    monkeypatch.setattr(browser, "_takeover_job", _fake_job)
    page = _Page({"cookies": [{"name": "PHPSESSID", "value": "1"}]})
    try:
        ok = browser.remote_takeover_solve(page, "https://x.test", "reCAPTCHA", 1000)
        assert ok is True
        assert browser.get_solved_state() == clearance
        assert handed["session_state"] == {"cookies": [{"name": "PHPSESSID", "value": "1"}]}
        assert handed["url"] == "https://x.test"
    finally:
        browser.reset_solved_state()


def test_remote_takeover_solve_returns_false_on_timeout(monkeypatch) -> None:
    """When the headed job yields no clearance (analyst never solved), the scan
    continues without any stashed state."""
    browser.reset_solved_state()
    monkeypatch.setattr(browser, "_takeover_job", lambda *a: None)
    try:
        ok = browser.remote_takeover_solve(_Page(), "https://x.test", "hCaptcha", 1000)
        assert ok is False
        assert browser.get_solved_state() is None
    finally:
        browser.reset_solved_state()


# ---------------------------------------------------------------------------
# _replay_clearance_and_reload
# ---------------------------------------------------------------------------

def test_replay_clearance_injects_cookies_and_reloads() -> None:
    cookies = [{"name": "cf_clearance", "value": "v"}]
    browser._ctx_tls.solved_state = {"cookies": cookies}
    page = _Page()
    try:
        browser._replay_clearance_and_reload(page, "https://x.test/gate")
    finally:
        browser.reset_solved_state()

    assert page.context.added == cookies
    assert page.goto_args is not None and page.goto_args[0] == "https://x.test/gate"


def test_replay_clearance_is_noop_without_state() -> None:
    browser.reset_solved_state()
    page = _Page()
    browser._replay_clearance_and_reload(page, "https://x.test")
    assert page.context.added is None
    assert page.goto_args is None


# ---------------------------------------------------------------------------
# navigate_with_bypass — human-present (web takeover) branch
# ---------------------------------------------------------------------------

def _patch_nav(monkeypatch, provider: str, solved: bool):
    """Stub navigate_with_bypass deps so only the takeover branch is exercised."""
    monkeypatch.setattr(browser, "_simulate_human_behavior", lambda p: None)
    monkeypatch.setattr(browser, "_is_cloudflare_phishing_block", lambda p: False)
    monkeypatch.setattr(browser, "detect_interactive_captcha", lambda p: provider)

    calls = {"solve": False, "replay": False, "cli": False}

    def _fake_takeover(page, url, prov, timeout_ms):
        calls["solve"] = True
        return solved

    monkeypatch.setattr(browser, "remote_takeover_solve", _fake_takeover)
    monkeypatch.setattr(
        browser, "_replay_clearance_and_reload",
        lambda p, u: calls.__setitem__("replay", True),
    )
    # The web path must never fall into the CLI manual-solve.
    monkeypatch.setattr(
        browser, "wait_for_manual_captcha_solve",
        lambda p, prov: calls.__setitem__("cli", True),
    )
    return calls


def test_navigate_hands_off_and_replays_when_solved(monkeypatch) -> None:
    calls = _patch_nav(monkeypatch, provider="reCAPTCHA", solved=True)
    browser.set_human_present(True)
    browser.set_interactive_mode(False)
    try:
        status = browser.navigate_with_bypass(_Page(), "https://x.test")
    finally:
        browser.set_human_present(False)

    assert status == 200
    assert calls["solve"] is True
    assert calls["replay"] is True, "a solved takeover must replay clearance past the gate"
    assert calls["cli"] is False, "web takeover must not use the CLI manual-solve path"


def test_navigate_skips_replay_when_takeover_unsolved(monkeypatch) -> None:
    calls = _patch_nav(monkeypatch, provider="reCAPTCHA", solved=False)
    browser.set_human_present(True)
    browser.set_interactive_mode(False)
    try:
        browser.navigate_with_bypass(_Page(), "https://x.test")
    finally:
        browser.set_human_present(False)

    assert calls["solve"] is True
    assert calls["replay"] is False, "no clearance to replay when the analyst didn't solve"


def test_navigate_no_takeover_without_human_present(monkeypatch) -> None:
    """A gate seen on a non-interactive, non-human scan (bulk/agent) notifies but
    never hands off to a human."""
    calls = _patch_nav(monkeypatch, provider="reCAPTCHA", solved=True)
    browser.set_human_present(False)
    browser.set_interactive_mode(False)
    browser.navigate_with_bypass(_Page(), "https://x.test")

    assert calls["solve"] is False
    assert calls["replay"] is False


def teardown_function(_func) -> None:
    browser.set_human_present(False)
    browser.set_interactive_mode(False)
    browser.set_action_notifier(None)
    browser.reset_solved_state()
