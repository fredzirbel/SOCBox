"""Authentication for IRIS.

Analysts log in via **OIDC SSO** (Azure AD / Okta); the AI triage agent / SOAR
authenticates with a **bearer service token**. Every page, ``/api/*``,
``/stream`` (SSE), and ``/screenshots`` requires a valid signed-session cookie
**or** a valid service token.

The SSE-heavy UI is why we accept a session cookie at all — ``EventSource``
can't send an ``Authorization`` header, but the browser sends the cookie
automatically same-origin.

Modes (``auth.mode``):
- ``oidc``     — production SSO (requires discovery_url / client_id / secret /
                 session_secret, supplied via env; the server refuses to start
                 otherwise).
- ``dev``      — INSECURE auto-login for local testing (gated by IRIS_AUTH_DEV=1).
- ``disabled`` — no auth (air-gapped use only).

The enforcer is a **pure-ASGI** middleware (not BaseHTTPMiddleware) so it never
buffers responses and stays compatible with the SSE streams.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import urlparse

from authlib.integrations.starlette_client import OAuth
from starlette.datastructures import MutableHeaders
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

logger = logging.getLogger(__name__)

# Paths reachable without authentication.
_PUBLIC_EXACT = {"/login", "/logout", "/auth/callback", "/health", "/favicon.ico"}
_API_PREFIXES = ("/api", "/stream", "/screenshots")

_DEV_USER = {"email": "dev@local", "sub": "dev"}
_OIDC_NAME = "iris_idp"

# Module state, set by init_auth().
_cfg: dict[str, Any] = {}
_oauth: OAuth | None = None


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _auth(cfg: dict[str, Any]) -> dict[str, Any]:
    return cfg.get("auth", {}) or {}


def effective_mode(cfg: dict[str, Any]) -> str:
    return _auth(cfg).get("mode", "oidc")


def _service_tokens(cfg: dict[str, Any]) -> list[str]:
    return list(_auth(cfg).get("service_tokens", []) or [])


def oidc_missing(cfg: dict[str, Any]) -> list[str]:
    """Return the list of required OIDC settings that are absent."""
    oidc = _auth(cfg).get("oidc", {}) or {}
    missing = [k for k in ("discovery_url", "client_id") if not oidc.get(k)]
    if not oidc.get("client_secret"):
        missing.append("oidc.client_secret (IRIS_OIDC_CLIENT_SECRET)")
    if not _auth(cfg).get("session_secret"):
        missing.append("session_secret (IRIS_SESSION_SECRET)")
    return missing


def _is_public_path(path: str) -> bool:
    return path in _PUBLIC_EXACT or path.startswith("/static/")


def _is_api_path(path: str) -> bool:
    return path.startswith(_API_PREFIXES)


def _valid_bearer(request: Request) -> bool:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False
    presented = header[7:].strip()
    tokens = _service_tokens(_cfg)
    return bool(presented) and any(secrets.compare_digest(presented, t) for t in tokens)


def current_user(request: Request) -> dict | None:
    """Return the logged-in user dict (``{email, sub}``) or None."""
    try:
        return request.session.get("user")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Enforcement middleware (pure ASGI — SSE-safe)
# ---------------------------------------------------------------------------

class AuthMiddleware:
    """Require a session cookie or bearer token on every non-public route."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        mode = effective_mode(_cfg)

        if mode == "disabled" or _is_public_path(path):
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        if mode == "dev":
            # INSECURE local auto-login; SessionMiddleware (outer) persists it.
            request.session["user"] = _DEV_USER
            await self.app(scope, receive, send)
            return

        authed = bool(request.session.get("user")) or _valid_bearer(request)
        if authed:
            await self.app(scope, receive, send)
            return

        if _is_api_path(path):
            response: Any = JSONResponse({"error": "Unauthorized"}, status_code=401)
        else:
            response = RedirectResponse(url="/login", status_code=302)
        await response(scope, receive, send)


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

def init_auth(app: Any, config: dict[str, Any]) -> None:
    """Wire session + auth middleware, OIDC client, and the auth routes.

    Safe to call at import time — never raises. Hard fail-closed validation for
    a misconfigured OIDC deployment happens in ``verify_auth_or_exit`` at server
    startup, so the CLI and tests (which only import the app) load cleanly.
    """
    global _cfg, _oauth
    _cfg = config
    mode = effective_mode(config)

    if mode == "oidc" and not oidc_missing(config):
        oidc = _auth(config)["oidc"]
        _oauth = OAuth()
        _oauth.register(
            name=_OIDC_NAME,
            server_metadata_url=oidc["discovery_url"],
            client_id=oidc["client_id"],
            client_secret=oidc["client_secret"],
            client_kwargs={"scope": oidc.get("scopes", "openid email profile")},
        )

    # Session secret: real one for oidc/prod (env), ephemeral for dev/disabled.
    session_secret = _auth(config).get("session_secret") or secrets.token_urlsafe(32)

    # Add INNER first, OUTER last: SessionMiddleware must run before the enforcer
    # so request.session is populated when AuthMiddleware reads it.
    app.add_middleware(AuthMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        same_site="lax",
        https_only=False,  # internal/VPN may be plain HTTP; set True behind TLS
        max_age=8 * 3600,
    )

    _register_routes(app)


def _register_routes(app: Any) -> None:
    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/login")
    async def login(request: Request) -> Any:
        if effective_mode(_cfg) != "oidc" or _oauth is None:
            # dev/disabled (or misconfigured oidc) — nothing to redirect to.
            return RedirectResponse(url="/")
        oidc = _auth(_cfg).get("oidc", {})
        redirect_uri = oidc.get("redirect_url") or str(request.url_for("auth_callback"))
        client = _oauth.create_client(_OIDC_NAME)
        return await client.authorize_redirect(request, redirect_uri)

    @app.get("/auth/callback", name="auth_callback")
    async def auth_callback(request: Request) -> Any:
        if _oauth is None:
            return RedirectResponse(url="/")
        client = _oauth.create_client(_OIDC_NAME)
        token = await client.authorize_access_token(request)
        info = token.get("userinfo") or {}
        request.session["user"] = {"email": info.get("email"), "sub": info.get("sub")}
        logger.info("OIDC login: %s", info.get("email"))
        return RedirectResponse(url="/")

    @app.get("/logout")
    async def logout(request: Request) -> RedirectResponse:
        request.session.clear()
        return RedirectResponse(url="/login")


# ---------------------------------------------------------------------------
# Security headers (pure ASGI — SSE-safe)
# ---------------------------------------------------------------------------

def _novnc_origin(config: dict[str, Any]) -> str:
    url = (config.get("interactive", {}) or {}).get("novnc_public_url", "") \
        or "http://localhost:6080/vnc.html"
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else "http://localhost:6080"


def build_csp(config: dict[str, Any]) -> str:
    """Content-Security-Policy.

    Keeps ``'unsafe-inline'`` for now because the templates use inline
    ``<script>`` + ``onclick``; allows Google Fonts and the noVNC live-solver
    iframe origin. Tightening to nonces (dropping unsafe-inline) is a follow-up.
    """
    novnc = _novnc_origin(config)
    return "; ".join([
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data:",
        f"frame-src 'self' {novnc}",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ])


class SecurityHeadersMiddleware:
    """Add security response headers without buffering (SSE-safe)."""

    def __init__(self, app: Any, csp: str = "") -> None:
        self.app = app
        self.csp = csp

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "SAMEORIGIN")
                headers.setdefault("Referrer-Policy", "no-referrer")
                if self.csp:
                    headers.setdefault("Content-Security-Policy", self.csp)
            await send(message)

        await self.app(scope, receive, send_wrapper)


def verify_auth_or_exit(config: dict[str, Any]) -> None:
    """Fail-closed startup check. Call from the server entrypoint (main())."""
    import sys

    mode = effective_mode(config)
    if mode == "oidc":
        missing = oidc_missing(config)
        if missing:
            logger.critical(
                "auth.mode=oidc but missing required config: %s — refusing to start. "
                "Set them via env (IRIS_OIDC_CLIENT_SECRET, IRIS_SESSION_SECRET, …) "
                "or use IRIS_AUTH_DEV=1 for local testing.",
                ", ".join(missing),
            )
            sys.exit(1)
        logger.info("Auth: OIDC SSO enabled.")
    elif mode == "dev":
        logger.warning("⚠ Auth in DEV mode — auto-login enabled. NOT for production.")
    elif mode == "disabled":
        logger.warning("⚠ Auth DISABLED — all endpoints are open (air-gapped use only).")
    else:
        logger.critical("Unknown auth.mode=%r — refusing to start.", mode)
        sys.exit(1)
