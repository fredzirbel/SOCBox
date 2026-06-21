"""Tests for the transparent noVNC CAPTCHA-solve takeover plumbing.

Covers the two non-browser-bound pieces:
  1. Per-scan, thread-local control state in ``iris.browser`` — an interactive /
     human-present scan must not leak its mode onto a concurrent headless scan.
  2. The app-side noVNC session token + view_url helpers that gate the live
     viewer. (The headed/noVNC paths themselves are container-bound and covered
     by live verification, not unit tests.)
"""

from __future__ import annotations

import threading

import iris.browser as browser
import iris.web.app as app

# ---------------------------------------------------------------------------
# Thread-local control state isolation
# ---------------------------------------------------------------------------

def test_human_present_is_thread_local() -> None:
    """One scan being human-present must not flip the flag for a sibling thread."""
    browser.set_human_present(False)
    seen: dict[str, bool] = {}

    def worker() -> None:
        browser.set_human_present(True)
        browser.set_interactive_mode(True)
        seen["worker_human"] = browser._human_present()
        seen["worker_interactive"] = browser._interactive_mode()

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    assert seen["worker_human"] is True
    assert seen["worker_interactive"] is True
    # The main thread never opted in — it must still see the defaults.
    assert browser._human_present() is False
    assert browser._interactive_mode() is False


def test_action_notifier_is_thread_local() -> None:
    """Concurrent scans must not clobber each other's action notifier."""
    browser.set_action_notifier(None)
    captured: dict[str, object] = {}

    def worker() -> None:
        marker = []
        browser.set_action_notifier(marker.append)
        captured["worker_cb"] = browser._get_action_notifier()

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    assert callable(captured["worker_cb"])
    assert browser._get_action_notifier() is None  # main thread untouched


def test_solve_timeout_defaults_and_override() -> None:
    """The per-scan solve timeout falls back to the module default, then honours
    an explicit override."""
    # Fresh thread → default.
    out: dict[str, int] = {}

    def worker() -> None:
        out["default"] = browser._solve_timeout_ms()
        browser.set_solve_timeout_ms(300_000)
        out["override"] = browser._solve_timeout_ms()

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    assert out["default"] == browser._CAPTCHA_SOLVE_TIMEOUT_MS
    assert out["override"] == 300_000


# ---------------------------------------------------------------------------
# noVNC session token + view_url
# ---------------------------------------------------------------------------

def test_token_issue_and_validate() -> None:
    token = app._issue_takeover_token(60)
    assert app._validate_takeover_token(token) is True
    assert app._validate_takeover_token("not-a-real-token") is False
    assert app._validate_takeover_token("") is False


def test_token_expires() -> None:
    token = app._issue_takeover_token(-1)  # already expired
    assert app._validate_takeover_token(token) is False


def test_build_view_url_includes_token_and_password(monkeypatch) -> None:
    monkeypatch.setitem(
        app._config, "interactive",
        {
            "novnc_public_url": "http://host:6080/vnc.html",
            "vnc_password": "s3cret pw",
        },
    )
    url = app._build_view_url("TOK123")
    assert url.startswith("http://host:6080/vnc.html?")
    assert "token=TOK123" in url
    assert "autoconnect=true" in url
    # Password is URL-encoded (space -> %20).
    assert "password=s3cret%20pw" in url


def test_build_view_url_omits_password_when_unset(monkeypatch) -> None:
    monkeypatch.setitem(
        app._config, "interactive",
        {"novnc_public_url": "http://host:6080/vnc.html", "vnc_password": ""},
    )
    url = app._build_view_url("TOK")
    assert "password=" not in url
    assert "token=TOK" in url


def test_is_human_present_public_accessor() -> None:
    browser.set_human_present(True)
    assert browser.is_human_present() is True
    browser.set_human_present(False)
    assert browser.is_human_present() is False


def test_get_solved_state_roundtrip() -> None:
    browser.reset_solved_state()
    assert browser.get_solved_state() is None
    state = {"cookies": [{"name": "cf_clearance"}]}
    browser._ctx_tls.solved_state = state
    assert browser.get_solved_state() == state
    browser.reset_solved_state()


def test_scan_concurrency_is_clamped() -> None:
    """Bulk concurrency must stay within the hard cap to avoid OOM."""
    assert 1 <= app._MAX_CONCURRENT_SCANS <= 8


def teardown_function(_func) -> None:
    """Reset process/thread state touched by these tests."""
    browser.set_human_present(False)
    browser.set_interactive_mode(False)
    browser.set_action_notifier(None)
    with app._takeover_tokens_lock:
        app._takeover_tokens.clear()
