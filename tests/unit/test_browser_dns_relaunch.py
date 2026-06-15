"""Regression tests for the thread-local browser DNS-relaunch logic.

Chromium fixes ``--host-resolver-rules`` at launch time, so a browser
cached for one URL cannot reach a different domain that needs its own
DoH-resolved MAP rule. ``_get_browser`` must relaunch the cached browser
whenever the required host-resolver rule changes; otherwise every URL after
the first one a worker thread scans silently fails to load (and screenshots
come back empty). These tests pin that behaviour.
"""

from __future__ import annotations

import iris.scanner as scanner


class _FakeBrowser:
    """Minimal stand-in for a Playwright Browser."""

    def __init__(self) -> None:
        self.closed = False

    @property
    def contexts(self):  # accessed by _get_browser's health check
        if self.closed:
            raise RuntimeError("browser is closed")
        return []

    def close(self) -> None:
        self.closed = True


class _FakePlaywright:
    def stop(self) -> None:
        pass


def _reset_thread_state() -> None:
    """Clear any thread-local browser state left by other tests."""
    scanner._tls.pw = None
    scanner._tls.browser = None
    scanner._tls.resolver_rule = ""
    with scanner._all_browsers_lock:
        scanner._all_browsers.clear()


def _patch(monkeypatch, rules: dict[str, str], launches: list) -> None:
    """Wire fakes so _get_browser is fully offline and observable.

    Args:
        rules: Maps a URL to the host-resolver rule it should require.
        launches: A list that each launch appends its new browser to,
            letting the test count launches.
    """
    monkeypatch.setattr(
        scanner, "compute_host_resolver_rule", lambda url: rules.get(url, "")
    )

    class _FakeSyncPlaywright:
        def start(self) -> _FakePlaywright:
            return _FakePlaywright()

    monkeypatch.setattr(scanner, "sync_playwright", lambda: _FakeSyncPlaywright())

    def _fake_launch(pw, url):
        browser = _FakeBrowser()
        launches.append(browser)
        return browser

    monkeypatch.setattr(scanner, "launch_browser", _fake_launch)


def test_same_dns_rule_reuses_cached_browser(monkeypatch) -> None:
    _reset_thread_state()
    launches: list = []
    _patch(monkeypatch, rules={}, launches=launches)  # all URLs resolve normally

    _, b1 = scanner._get_browser("https://example.com")
    _, b2 = scanner._get_browser("https://another-normal-site.com")

    assert len(launches) == 1, "browser should be reused when the rule is unchanged"
    assert b1 is b2

    _reset_thread_state()


def test_changed_dns_rule_relaunches_browser(monkeypatch) -> None:
    _reset_thread_state()
    launches: list = []
    # First URL needs a DoH MAP override; second is a different blocked host.
    rules = {
        "https://phish-one.test": "MAP phish-one.test 1.1.1.1",
        "https://phish-two.test": "MAP phish-two.test 2.2.2.2",
    }
    _patch(monkeypatch, rules=rules, launches=launches)

    _, b1 = scanner._get_browser("https://phish-one.test")
    _, b2 = scanner._get_browser("https://phish-two.test")

    assert len(launches) == 2, "browser must relaunch when the host-resolver rule changes"
    assert b1 is not b2
    assert b1.closed, "stale browser should be closed on relaunch"

    _reset_thread_state()


def test_override_then_normal_url_relaunches(monkeypatch) -> None:
    """A browser launched with a MAP rule must not be reused for a normal URL."""
    _reset_thread_state()
    launches: list = []
    rules = {"https://phish.test": "MAP phish.test 3.3.3.3"}  # normal URL -> "" rule
    _patch(monkeypatch, rules=rules, launches=launches)

    scanner._get_browser("https://phish.test")          # rule = MAP ...
    scanner._get_browser("https://legit-example.com")   # rule = ""

    assert len(launches) == 2, "stale MAP rule must not leak onto a normal URL"

    _reset_thread_state()
