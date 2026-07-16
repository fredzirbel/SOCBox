"""Tests for the auth enforcement (OIDC session / bearer token / dev / disabled)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import socbox.web.app as app_module
import socbox.web.auth as auth
from socbox.web.app import app

client = TestClient(app)


def _set_auth(mode: str, tokens: list[str] | None = None) -> None:
    auth._cfg["auth"] = {"mode": mode, "service_tokens": tokens or [], "oidc": {}}


@pytest.fixture(autouse=True)
def _restore_auth():
    original = auth._cfg.get("auth")
    yield
    auth._cfg["auth"] = original


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def test_unauthenticated_api_returns_401() -> None:
    _set_auth("oidc")
    assert client.get("/api/results/whatever").status_code == 401
    assert client.get("/stream/whatever").status_code == 401


def test_unauthenticated_html_redirects_to_login() -> None:
    _set_auth("oidc")
    r = client.get("/results/whatever", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_public_paths_need_no_auth() -> None:
    _set_auth("oidc")
    assert client.get("/health").status_code == 200
    # /login is public (it initiates the SSO flow / redirects)
    assert client.get("/login", follow_redirects=False).status_code in (302, 307, 200)


def test_valid_bearer_token_passes_auth() -> None:
    _set_auth("oidc", tokens=["s3cret-token"])
    r = client.get("/api/results/nope", headers={"Authorization": "Bearer s3cret-token"})
    assert r.status_code != 401  # auth passed (endpoint then 404s the unknown id)


def test_wrong_bearer_token_is_rejected() -> None:
    _set_auth("oidc", tokens=["right-token"])
    r = client.get("/api/results/nope", headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


def test_dev_mode_auto_logs_in() -> None:
    _set_auth("dev")
    assert client.get("/api/results/nope").status_code != 401


def test_disabled_mode_is_open() -> None:
    _set_auth("disabled")
    assert client.get("/api/results/nope").status_code != 401


# ---------------------------------------------------------------------------
# Config validation helpers
# ---------------------------------------------------------------------------

def test_oidc_missing_flags_required_settings() -> None:
    missing = auth.oidc_missing({"auth": {"mode": "oidc", "oidc": {}}})
    assert "discovery_url" in missing
    assert "client_id" in missing
    assert any("client_secret" in m for m in missing)
    assert any("session_secret" in m for m in missing)


def test_scan_endpoint_is_rate_limited(monkeypatch) -> None:
    """The scan endpoint enforces the configured per-minute cap (429)."""
    _set_auth("dev")  # auto-login so we reach the rate limiter
    monkeypatch.setitem(
        app_module._config.setdefault("ratelimit", {}), "scan_per_minute", 1
    )
    # 127.0.0.1 is SSRF-blocked (400) so no real scan runs, but it still
    # consumes the rate-limit token; the second call should be 429.
    body = {"url": "http://127.0.0.1/"}
    client.post("/api/scan", json=body)
    assert client.post("/api/scan", json=body).status_code == 429


def test_oidc_missing_empty_when_fully_configured() -> None:
    cfg = {
        "auth": {
            "mode": "oidc",
            "session_secret": "x" * 32,
            "oidc": {
                "discovery_url": "https://idp/.well-known",
                "client_id": "c",
                "client_secret": "s",
            },
        }
    }
    assert auth.oidc_missing(cfg) == []
