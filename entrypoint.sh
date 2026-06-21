#!/usr/bin/env bash
# =============================================================================
# IRIS container entrypoint
# =============================================================================
# Brings up a *fixed* virtual display, exports it over noVNC, then launches the
# app. The fixed display (vs. the previous `xvfb-run --auto-servernum`) lets
# x11vnc attach deterministically so the transparent CAPTCHA-solve takeover can
# stream the headed detonation browser into an analyst's tab.
#
# SECURITY: the noVNC gateway is a live, controllable browser on malicious
# pages. x11vnc binds to localhost and only the noVNC port is published; set
# VNC_PASSWORD and keep this endpoint behind API auth / SSO (item #6) or a VPN.
# =============================================================================
set -euo pipefail

DISPLAY_NUM="${DISPLAY_NUM:-:99}"
XVFB_GEOMETRY="${XVFB_GEOMETRY:-1920x1080x24}"
NOVNC_PORT="${NOVNC_PORT:-6080}"
VNC_PORT=5900

export DISPLAY="${DISPLAY_NUM}"

# Clear stale X locks/sockets left by a previous run. On `docker restart` (and
# the restart:unless-stopped recovery path) the container filesystem persists,
# so a leftover /tmp/.X99-lock would make Xvfb fail and crash-loop the entrypoint.
disp_n="${DISPLAY_NUM#:}"
rm -f "/tmp/.X${disp_n}-lock" "/tmp/.X11-unix/X${disp_n}" 2>/dev/null || true

# --- Virtual display: headed Chrome (CAPTCHA takeover) renders here ----------
Xvfb "${DISPLAY_NUM}" -screen 0 "${XVFB_GEOMETRY}" -nolisten tcp &
# Wait for the X socket so x11vnc/Chrome don't race the display coming up.
for _ in $(seq 1 50); do
    [ -S "/tmp/.X11-unix/X${DISPLAY_NUM#:}" ] && break
    sleep 0.1
done

# --- VNC server: export the display, localhost-only --------------------------
vnc_args=(-display "${DISPLAY_NUM}" -forever -shared -localhost -bg -quiet -noxdamage)
if [ -n "${VNC_PASSWORD:-}" ]; then
    mkdir -p /run/iris
    x11vnc -storepasswd "${VNC_PASSWORD}" /run/iris/vncpass >/dev/null 2>&1
    vnc_args+=(-rfbauth /run/iris/vncpass)
else
    echo "[entrypoint] WARNING: VNC_PASSWORD unset — starting x11vnc with no password" >&2
    vnc_args+=(-nopw)
fi
x11vnc "${vnc_args[@]}"

# --- noVNC web gateway: ws bridge :6080 <-> VNC :5900, serving the client -----
websockify --web=/usr/share/novnc "${NOVNC_PORT}" "localhost:${VNC_PORT}" &

# --- The app -----------------------------------------------------------------
exec python -m iris.web.app --no-reload
