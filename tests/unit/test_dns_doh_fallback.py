"""Tests for the DoH-aware HTTP request fallback in ``socbox.dns_util``.

The requests-based analyzers (HTTP, download, threat feeds) reach the target
host through ``request_with_doh_fallback``.  When the system resolver fails
for the target host, the helper must resolve it via public DoH and retry the
request with a thread-local getaddrinfo override - leaving SNI, TLS, and the
URL untouched.  These tests pin that behaviour without any real network I/O.
"""

from __future__ import annotations

import socket

import requests

import socbox.dns_util as dns_util


class _FakeSession:
    """Duck-typed stand-in for ``requests.Session`` that records calls.

    The first call raises ``fail_first_with`` (when given); the retry returns
    a 200 response and captures whatever DoH override is active at that moment.
    """

    def __init__(self, fail_first_with: BaseException | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._fail = fail_first_with
        self.override_seen: dict[str, str] | None = None

    def request(self, method: str, url: str, **kwargs: object) -> requests.Response:
        self.calls.append((method, url))
        if len(self.calls) == 1 and self._fail is not None:
            raise self._fail

        self.override_seen = dict(getattr(dns_util._local, "dns_overrides", {}) or {})
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b"ok"
        resp.url = url
        return resp


def _dns_connection_error() -> requests.exceptions.ConnectionError:
    """A ConnectionError whose cause chain is a name-resolution failure."""
    err = requests.exceptions.ConnectionError("Failed to establish a new connection")
    err.__cause__ = socket.gaierror(-2, "Name or service not known")
    return err


def _clear_overrides() -> None:
    dns_util._local.dns_overrides = {}


def test_no_failure_returns_first_response(monkeypatch) -> None:
    """A successful request is returned as-is, with no DoH resolution."""
    _clear_overrides()
    called = {"doh": False}
    monkeypatch.setattr(
        dns_util, "_resolve_via_doh",
        lambda h: (called.__setitem__("doh", True) or "9.9.9.9"),
    )

    sess = _FakeSession()
    resp = dns_util.request_with_doh_fallback(
        "GET", "https://example.com/path", session=sess,
    )

    assert resp.status_code == 200
    assert len(sess.calls) == 1
    assert called["doh"] is False, "DoH must not run when the request succeeds"


def test_dns_failure_retries_via_doh_override(monkeypatch) -> None:
    """A DNS failure triggers a DoH-resolved retry with the host overridden."""
    _clear_overrides()
    monkeypatch.setattr(dns_util, "_resolve_via_doh", lambda h: "1.2.3.4")

    sess = _FakeSession(fail_first_with=_dns_connection_error())
    resp = dns_util.request_with_doh_fallback(
        "GET", "https://blocked-phish.test/login", session=sess,
    )

    assert resp.status_code == 200
    assert len(sess.calls) == 2, "should retry exactly once after a DNS failure"
    # The retry saw the DoH override mapping the target host to the DoH IP.
    assert sess.override_seen == {"blocked-phish.test": "1.2.3.4"}
    # The URL itself is never rewritten to the IP (SNI/cert stay intact).
    assert sess.calls[1] == ("GET", "https://blocked-phish.test/login")


def test_override_is_cleaned_up_after_call(monkeypatch) -> None:
    """The thread-local override must not leak past the request."""
    _clear_overrides()
    monkeypatch.setattr(dns_util, "_resolve_via_doh", lambda h: "1.2.3.4")

    sess = _FakeSession(fail_first_with=_dns_connection_error())
    dns_util.request_with_doh_fallback("GET", "https://x.test", session=sess)

    assert dict(dns_util._local.dns_overrides) == {}


def test_non_dns_error_is_not_retried() -> None:
    """A non-DNS connection error propagates without a retry."""
    _clear_overrides()
    sess = _FakeSession(
        fail_first_with=requests.exceptions.ConnectionError("Connection refused"),
    )

    try:
        dns_util.request_with_doh_fallback("GET", "https://x.test", session=sess)
    except requests.exceptions.ConnectionError:
        pass
    else:  # pragma: no cover - failure path
        raise AssertionError("expected ConnectionError to propagate")

    assert len(sess.calls) == 1, "non-DNS errors must not be retried"


def test_dns_failure_with_unresolvable_host_reraises(monkeypatch) -> None:
    """If DoH also cannot resolve the host, the original error propagates."""
    _clear_overrides()
    monkeypatch.setattr(dns_util, "_resolve_via_doh", lambda h: "")

    sess = _FakeSession(fail_first_with=_dns_connection_error())

    try:
        dns_util.request_with_doh_fallback("GET", "https://x.test", session=sess)
    except requests.exceptions.ConnectionError:
        pass
    else:  # pragma: no cover - failure path
        raise AssertionError("expected ConnectionError to propagate")

    assert len(sess.calls) == 1, "no retry when DoH cannot resolve the host"


def test_is_dns_failure_detection() -> None:
    """_is_dns_failure spots gaierror and resolver error markers in the chain."""
    assert dns_util._is_dns_failure(socket.gaierror(-2, "Name or service not known"))
    assert dns_util._is_dns_failure(_dns_connection_error())
    assert dns_util._is_dns_failure(
        requests.exceptions.ConnectionError("Temporary failure in name resolution")
    )
    assert not dns_util._is_dns_failure(
        requests.exceptions.ConnectionError("Connection refused by peer")
    )
