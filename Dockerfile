# =============================================================================
# SOC Box - The SOC Analyst's Toolbox (containerised)
# =============================================================================
# Build:  docker compose up --build
# Access: http://localhost:8000
# =============================================================================

FROM python:3.11-slim AS base

# ── System packages ──────────────────────────────────────────────────────────
# - wget/gnupg/curl: needed to add Google Chrome apt repo
# - xvfb: virtual framebuffer so headed Chrome can run without a real display
# - x11vnc/novnc/websockify: export the display so analysts can solve CAPTCHAs
#   live in the browser (transparent noVNC takeover)
# - fonts-liberation/libnss3/etc: Chrome runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        gnupg \
        curl \
        ca-certificates \
        xvfb \
        xauth \
        x11vnc \
        novnc \
        websockify \
        fonts-liberation \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcups2 \
        libdbus-1-3 \
        libdrm2 \
        libgbm1 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libx11-xcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# ── Google Chrome stable ─────────────────────────────────────────────────────
# Required for Cloudflare Turnstile bypass (headed mode with real TLS fingerprint)
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub \
        | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] \
        http://dl.google.com/linux/chrome/deb/ stable main" \
        > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# ── Application directory ────────────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies (cached layer) ───────────────────────────────────────
COPY pyproject.toml ./
COPY src/ ./src/
COPY config/default.yaml ./config/default.yaml
RUN pip install --no-cache-dir . \
    && playwright install --with-deps chromium

# ── Copy remaining project files ─────────────────────────────────────────────
COPY . .

# ── Screenshot output directory ──────────────────────────────────────────────
RUN mkdir -p /app/screenshots

# ── Expose the web UI + noVNC ports ──────────────────────────────────────────
EXPOSE 8000
EXPOSE 6080

# ── Entrypoint: fixed Xvfb display + x11vnc + noVNC, then the app ────────────
# Replaces the old `xvfb-run --auto-servernum` so the display number is fixed
# and x11vnc can attach deterministically for the live CAPTCHA-solve takeover.
# Strip any CR before chmod: a Windows checkout (git autocrlf) can give the
# script CRLF endings, which make bash fail with "set: pipefail: invalid option
# name". This keeps the image buildable regardless of the host's git config.
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh
CMD ["bash", "/app/entrypoint.sh"]
