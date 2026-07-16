"""Tests for the human-like behaviour simulation used to improve
invisible / score-based challenge pass rates (reCAPTCHA v3, Turnstile).
"""

from __future__ import annotations

import socbox.browser as browser


class _FakeMouse:
    def __init__(self) -> None:
        self.moves: list[tuple[int, int]] = []
        self.wheels: list[tuple[int, int]] = []

    def move(self, x, y, steps=1):
        self.moves.append((x, y))

    def wheel(self, dx, dy):
        self.wheels.append((dx, dy))


class _FakePage:
    def __init__(self) -> None:
        self.mouse = _FakeMouse()
        self.waited = 0

    def wait_for_timeout(self, ms):
        self.waited += ms


def test_simulate_human_behavior_moves_and_scrolls() -> None:
    page = _FakePage()

    browser._simulate_human_behavior(page)

    assert len(page.mouse.moves) == 3, "should make several mouse moves"
    assert len(page.mouse.wheels) == 2, "should scroll down then partway back up"
    assert page.mouse.wheels[0][1] > 0, "first scroll is downward"
    assert page.mouse.wheels[1][1] < 0, "second scroll is upward"
    assert page.waited > 0, "should include human-like dwell pauses"
    # Mouse moves stay within the configured viewport bounds.
    for x, y in page.mouse.moves:
        assert 0 <= x <= browser._VIEWPORT_WIDTH
        assert 0 <= y <= browser._VIEWPORT_HEIGHT


def test_simulate_human_behavior_never_raises() -> None:
    """A page that errors mid-interaction must not break the scan."""

    class _ExplodingPage:
        @property
        def mouse(self):
            raise RuntimeError("page navigated away")

        def wait_for_timeout(self, ms):
            pass

    # Should swallow the error and return cleanly.
    browser._simulate_human_behavior(_ExplodingPage())
