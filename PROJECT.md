# IRIS — Project Context & Status

**IRIS (Intelligent Risk Inspection System)** — a containerized URL/phishing analysis
platform. Scans a URL across 8 analyzers + threat feeds, detonates it in a real browser
(gets past Cloudflare/CAPTCHAs), classifies the attack technique (ATT&CK-mapped), and
returns a verdict, screenshot, page text, and final landing URL.

- **Repo:** https://github.com/fredzirbel/IRIS (branch `main`, all work pushed)
- **Local:** `C:\Users\Freddy\Desktop\Projects\Projects\IRIS`
- **Owner:** Fred Zirbel — Senior Security Analyst, Critical Start (MSSP/MDR/MSP)

## North star
Replace **SlashNext** (slow, costly, fails on CAPTCHAs) as the URL-investigation tool that
feeds the SOC's **AI triage agent** (pulls logs from MDE/CrowdStrike/SentinelOne) and
analysts. IRIS already beats SlashNext on its two worst pain points: it gets past
CAPTCHAs/click-throughs, and it's free/self-hosted. Alert dispositions use **TP / Benign TP
(BTP) / FP**. The machine verdict (Safe/Uncertain/Malicious) is separate from the analyst
disposition.

## Run it
- **Container (primary):** `docker compose up --build -d` → **http://localhost:8080**
  (host 8080 → container 8000; **8000 is unusable** — it's in a Windows/WinNAT reserved
  range 7908–8007). `restart: unless-stopped`. Also publishes **6080** (noVNC live-browser
  viewer for in-browser CAPTCHA solving; set `VNC_PASSWORD`).
- **Dev server:** `IRIS_PORT=8015 .venv/Scripts/python.exe -m iris.web.app --no-reload`
  (no noVNC/Xvfb — the live-solver takeover needs the container entrypoint).
- **Tests/lint:** `.venv/Scripts/python.exe -m pytest -q` (119 passing) · `... -m ruff check src tests`
  · `... -m bandit -ll -r src` · `... -m pip_audit --skip-editable`
- **Auth to run the server:** OIDC env (or `IRIS_AUTH_DEV=1` for an insecure local spin-up) —
  the server fail-closes otherwise.
- **CLI:** `iris <url>` · `iris <url> -i` (interactive CAPTCHA) · `python -m iris.feeds_import ...`

## Environment quirks (important)
- venv is **Python 3.14** at `.venv` (older than the 3.11 the Docker image uses).
- **Docker Desktop is flaky** here (an "Inference manager" socket error; daemon sometimes
  down). If `docker` fails, the user starts Docker Desktop manually.
- The static stylesheet/JS are **cache-busted** via a `?v=<mtime>` token (`_static_version`
  in `app.py` + `base.html`), so a normal refresh picks up CSS changes — no hard reload.
- PowerShell AMSI may block strings containing live malware/ClickFix payloads — create such
  fixtures via the Bash tool instead.

## Architecture
- `src/iris/scanner.py` — orchestrates analyzers (thread pool + a persistent thread-local
  Playwright browser via `_get_browser`), scoring, classification, screenshots. Emits SSE
  events through an `on_event` callback.
- `src/iris/analyzers/` — 8 analyzers (url_lexical, whois_dns, ssl_tls, http_response,
  page_content, link_discovery, download, threat_feeds). `page_content` also stashes
  `page_text` + scripts for classification.
- `src/iris/feeds/` — VirusTotal, AbuseIPDB, Google Safe Browsing.
- `src/iris/browser.py` — Playwright launch, Cloudflare bypass, **CAPTCHA solving**, human-like
  behavior, per-URL DNS via `--host-resolver-rules` (uses the DoH fallback in `dns_util`).
  Control state (`interactive` / `human_present` / `action_notifier` / solve timeout) is
  **thread-local, set per scan** (`set_*` fns) so concurrent scans don't interfere. Two solve
  modes: CLI inline (`wait_for_manual_captcha_solve`) and **web transparent takeover**
  (`remote_takeover_solve` → dedicated single-thread headed browser on the X display → noVNC;
  serialized on one display). Clearance is captured once and replayed across the scan
  (`_stash_solved_state`/`_ctx_tls.solved_state`, replayed by `create_context`).
- `src/iris/dns_util.py` — DoH resolution (`resolve_host`/`resolve_hostname`), Chromium
  `--host-resolver-rules` helpers, and `request_with_doh_fallback` — a thread-safe DoH
  retry wrapper for the **requests-based** analyzers (thread-local getaddrinfo override on
  a DNS-class `ConnectionError`; preserves SNI/TLS/redirects). Used by HTTP, download, and
  threat-feed IP resolution.
- `src/iris/scoring.py` — `calculate_score` + `_composite_parts` (shared math) +
  `score_breakdown` (per-analyzer contributions; 45% analyzers / 55% feeds blend + VT floor).
- `src/iris/classification.py` — rule-based ATT&CK technique tagging.
- `src/iris/store.py` — **SQLite** persistence (scans + TP/BTP/FP dispositions; queryable
  verdict history). DB at `screenshots/iris.db` (gitignored, on the mounted volume).
- `src/iris/feeds_import.py` — `iris-feeds` CLI; pulls live URLs from URLhaus (authed API)
  + OpenPhish.
- `src/iris/web/app.py` — FastAPI: web routes, SSE `/stream/{id}`, REST + **v1 TAP API**.
- `src/iris/web/templates/results.html` — **TWO render paths that must stay in sync**:
  streaming (`{% if streaming %}`, JS/SSE) and static (`{% else %}`, server-rendered Jinja).
- Shared UI handlers (lightbox, copy-link, copy-url, disposition buttons) live in `base.html`.
- **Desktop notifications** (Web Notifications API): CAPTCHA `action_required` gates, plus
  scan-complete (single) and batch-complete (Bulk, with malicious/error counts). All fire
  only when `document.hidden` (analyst tabbed away) so they never interrupt active viewing.

## v1 TAP API (the SlashNext replacement — agent/SOAR-callable)
All return `final_url`. Accept `{"url":...}` (runs a scan) or `?scan_id=` (reuses one).
- `POST /api/v1/url/scan` — full result (verdict, suggested_disposition, score, final_url,
  text, screenshot_url, classifications)
- `POST /api/v1/url/text` — `{final_url, text}`
- `POST /api/v1/url/screenshot` — `{final_url, screenshot_url}`
- `POST /api/v1/url/threat-intel` — `{final_url, verdict, suggested_disposition, ...}`
- `POST /api/v1/scan/{id}/disposition` — `{disposition: TP|BTP|FP, analyst, note}`
- `POST /api/v1/scan/async` — `{url, callback_url?}` → `{job_id}`; POSTs result to callback on done
- `GET /api/v1/scan/{job_id}` — poll async job
- `GET /api/feeds/import?source=urlhaus|openphish&limit=&tag=` — live URLs for Bulk Scan
- `GET /api/takeover/validate?token=` — noVNC session-token check (live-solver guard / websockify hook)

## Transparent in-browser CAPTCHA solving (#2)
- A single analyst-initiated **web** scan (`/api/scan` with `human_present:true` — the index
  single-scan form sets it) that hits an un-automatable CAPTCHA pauses and surfaces the **live
  detonation browser** in the analyst's tab via **self-hosted noVNC**; the scan resumes
  automatically once solved. **Bulk / agent (TAP) / async scans never block on a human.**
- Handoff: the headless scan hands the gate to a headed browser on the X display (dedicated
  single takeover thread → serialized on one display), replaying the scan's session; on solve
  it captures clearance and the headless scan reloads past the gate + replays it onward.
- Infra: container entrypoint (`entrypoint.sh`) runs `Xvfb :99` + `x11vnc -localhost` +
  `websockify`/noVNC on **6080**. Trigger is *presence* (no checkbox); covers CAPTCHA
  challenges (CTA "Continue/Download" gates are already auto-clicked).
- ⚠️ **Security:** the noVNC viewer is a controllable browser on malicious pages. v1 guard =
  `VNC_PASSWORD` (x11vnc) + a one-time `view_url` session token. It **MUST sit behind #6 API
  auth/SSO or a VPN before any network exposure.** `VNC_PASSWORD` (compose env) must match
  `interactive.vnc_password` (local.yaml).

## Security / hardening (auth, SSRF, rate limiting)
- **AuthN/AuthZ** ([web/auth.py](src/iris/web/auth.py)): analysts log in via **OIDC SSO**
  (Azure AD/Okta, Authlib) → signed session cookie; the agent uses **bearer service tokens**.
  A pure-ASGI enforcement middleware (SSE-safe) gates every page, `/api/*`, `/stream`, and
  `/screenshots`; unauth → 302 `/login` (HTML) or 401 (API). Public: `/static`, `/login`,
  `/auth/callback`, `/logout`, `/health`. `auth.mode` ∈ {`oidc`, `dev`, `disabled`}; **dev**
  (auto-login) requires `IRIS_AUTH_DEV=1`. Server **fail-closes** (main() exits) if oidc mode
  is missing config.
- **SSRF guard** ([netguard.py](src/iris/netguard.py)): every scan-entry rejects (400) targets
  resolving to private/loopback/link-local/metadata (169.254.169.254). `ssrf.block_private`
  (default true) + `ssrf.allowlist`.
- **Rate limiting** (slowapi): scan endpoints capped at `ratelimit.scan_per_minute` (default 30)
  per token/IP → 429.
- **Secure headers** (CSP w/ Google-Fonts + noVNC `frame-src`; X-Frame-Options, nosniff,
  Referrer-Policy) + `GET /health`. **CI**: bandit + pip-audit added (alongside ruff/pytest/
  gitleaks).
- ⚠️ **Secrets via env only** (never committed): `IRIS_SESSION_SECRET`,
  `IRIS_OIDC_CLIENT_SECRET`, `IRIS_API_TOKENS`. Compose passes them through.

## Config & secrets
- `config/default.yaml` (committed, empty slots) / `config/local.yaml` (**gitignored**, real keys).
- Keys present in local.yaml: virustotal, google_safebrowsing, abuseipdb, **urlhaus**.
- `notifications.webhook_url` (+ `webhook_timeout`) for async completion webhooks.
- `interactive.*` — enable flag, `novnc_public_url`, `vnc_password`, `session_timeout_ms`,
  `display` for the in-browser CAPTCHA solver (default **disabled**).
- `auth.*` / `ssrf.*` / `ratelimit.*` — see Security section above.
- ⚠️ **Rotate the URLhaus key** — it was pasted into a chat transcript.

## Done this session (all on `main`)
1. **Screenshot fix** — relaunch the cached browser when the per-URL host-resolver DNS rule
   changes (most URLs weren't screenshotting).
2. **Interactive CAPTCHA solving** — on-screen browser, detect/pause/resume, **solve-once**
   (clearance cookies replayed across the scan's multiple navigations). Human-behavior sim
   to lift invisible-challenge pass rate.
3. **Critical Start rebrand** — navy/cyan palette, Saira Condensed + Nunito Sans, CS logo
   lockup, **light/dark toggle**, animations. (Fixed a Starlette `TemplateResponse`
   signature bug that 500'd every page on current deps.)
4. **Threat classification tags** — ATT&CK-mapped (ClickFix T1204.004, encoded command
   T1027, credential phishing T1566.002, fake update T1189, tech-support T1656, clipboard
   hijack T1059, crypto drainer T1657, captcha-gated T1497).
5. **Screenshot UX** — click-to-zoom lightbox, "Copy screenshot URL" button, singular/plural title.
6. **Feed/OSINT merge** — feed rows link to reports; OSINT grid slimmed of duplicates.
7. **Analyzer breakdown rework** — Contribution column with bars, sorted by impact, threat
   feed shown as a separate blended line, default-open, score-explainer summary.
8. **Banner URLs** — defanged (primary, click-to-copy + tooltip) above fanged (plain text).
9. **`iris-feeds`** — import live malicious URLs (URLhaus authed API + OpenPhish): CLI,
   `/api/feeds/import`, and a Bulk Scan "Import from feed" button.
10. **v1 TAP API** + **TP/BTP/FP dispositions** + **SQLite persistence** + **async webhook**
    + **CAPTCHA `action_required` desktop notification**.

## Performance pass (latest session, on `main`)
Per-analyzer profiling of a single scan (`example.com`) drove two targeted fixes that
~halved wall-clock time — **dev box 23.9s → 11.8s** (and lower in the container, where
`dns: [1.1.1.1, 8.8.8.8]` makes the DNS lookups ~tens of ms instead of the dev router's
~2s each). Verdict/output contract unchanged; 94 tests / ruff / bandit green.
1. **Cue-aware download poll** ([analyzers/download.py](src/iris/analyzers/download.py)) —
   the browser-download fallback polled a fixed 12s for a download event on *every* scan,
   additive at the tail. Now releases a static landing page after 3s (genuine JS
   auto-downloads fire in ~1-2s) but still grants the full 12s when the page's visible text
   advertises a pending download ("preparing your file", "verifying", …). ~9s off the common
   case, no loss of delayed-payload detection. New `tests/unit/test_download_intent.py`.
2. **Dropped reverse-DNS PTR check** ([analyzers/whois_dns.py](src/iris/analyzers/whois_dns.py))
   — `socket.gethostbyaddr` ignored the configured resolvers, stalled ~4.5s before timing
   out, and gave near-zero signal (modern phishing is CDN-fronted → no meaningful PTR). It
   also spuriously dinged benign CDN sites. WHOIS domain age / NXDOMAIN / MX are unaffected.
   Note: WHOIS itself is cheap (~0.4s) — the old "WHOIS is slow" intuition was really the PTR
   lookup. The deferred Download analyzer can't start until the parallel phase's long pole
   finishes, so shrinking WHOIS/DNS also pulls everything after it earlier.

## Full code review & fixes (latest session, on `main`)
A complete line-by-line review against the SlashNext feature set surfaced 2 critical +
4 medium + 5 low issues; all fixed, criticals first. **119 tests / ruff / bandit green**;
full scan pipeline re-verified end-to-end. Commits `eac2504..c55426c`.
- 🔴 **SSL/TLS analyzer was inert on HTTPS** ([ssl_tls.py](src/iris/analyzers/ssl_tls.py)) —
  it connected with `CERT_NONE` then read `getpeercert(binary_form=False)`, which returns an
  **empty dict** when the peer cert isn't validated, so issuer / recently-issued / hostname-
  mismatch / expiry all silently no-opped (a 15%-weight analyzer scoring 0, and the strong
  "cert issued days ago" phishing signal lost). Subject-mismatch was doubly dead —
  `ssl.match_hostname` was removed in Python 3.12+. Now parses the DER cert with
  `cryptography.x509`; 10 network-free regression tests. `cryptography>=42` is now an explicit dep.
- 🔴 **Stored XSS in the analyst report** ([web/app.py](src/iris/web/app.py)) — `report_json`
  and `bulk_restore` were injected into `<script>` via `|safe` using `json.dumps`, which
  leaves `</script>` intact. Attacker-controlled fields (download filename, classification
  evidence, finding text) could break out and run JS in the analyst's authenticated session.
  New `_json_script_safe()` escapes `< > &` + U+2028/9.
- 🟠 SSRF hardening: DoH fallback refuses non-public results (`is_public_ip` in
  [dns_util.py](src/iris/dns_util.py)); async webhook `callback_url` is validated through the
  SSRF guard. 🟠 Response-body caps on the requests-based analyzers (HTTP streams headers-only;
  page-content caps at 3 MB) to stop memory-exhaustion from hostile servers. 🟠 Auto-reload is
  now opt-in (`--reload`/`IRIS_RELOAD=1`), not the prod default.
- 🟡 KQL-injection escaping in generated hunting queries; punycode/IDN (`xn--`) homograph
  detection; encoded-command classifier no longer false-positives on lone base64 blobs; **Safe**
  confidence now scales with evidence completeness; session-cookie `Secure` flag configurable
  (`auth.cookie_secure`). New `tests/unit/test_review_fixes.py` + `test_ssl_tls.py`.
- **SlashNext parity gaps still open** (not bugs): no QR-code / nested-link (obfuscation)
  detection; URL reputation leans on VirusTotal lookups (no active submission), so true
  zero-hour URLs have no VT data — the browser detonation partly compensates.

## Open / pending (next-session candidates, roughly prioritized)
- **#6 API auth** ✅ **DONE** — OIDC SSO (analysts) + bearer service tokens (agent) gate every
  page/`/api/*`/`/stream`/`/screenshots`; SSRF guard + rate limiting + secure headers + CI
  bandit/pip-audit added. See the **Security / hardening** section. *Real Azure AD round-trip
  to be confirmed in the SOC tenant (app registration + redirect URI).* Residual follow-ups:
  per-user RBAC; reverse-proxy the noVNC :6080 behind the app session (currently view_url is
  only handed to authenticated sessions, but :6080 itself is VNC-password-gated only);
  HMAC-signed webhooks; CSP nonces (drop `unsafe-inline`); non-root browser container.
  *(The review pass landed webhook `callback_url` SSRF validation and a configurable
  `auth.cookie_secure`; HMAC signing / CSP nonces / non-root / RBAC still open.)*
- **#2 in-browser CAPTCHA solve** ✅ **v1 DONE + Docker-verified** (see section above):
  transparent noVNC takeover, behind `interactive.enabled`. Verified end-to-end in the
  container — scanning the reCAPTCHA demo with `human_present` fired `action_required` +
  `view_url`, and the headed takeover browser rendered the live reCAPTCHA on display `:99`
  (confirmed by screenshotting the Xvfb display). Entrypoint now clears stale X locks so
  `docker restart` / `restart:unless-stopped` doesn't crash-loop. Remaining: the **human
  solve → resume → post-gate analysis** leg is inherently manual (analyst clicks the
  checkbox); per-provider tuning of the clearance "replay + reload"; a **multi-display
  pool** for concurrent takeovers (v1 serializes on one).
- Optional follow-up: **surface + reclassify the post-click landing page** (feed `cta_url`
  into `final_url` + reclassification + screenshot TAP) — complementary to #2, not yet done.
- ~~**DNS robustness**~~ ✅ **DONE** (all three): `dns: [1.1.1.1, 8.8.8.8]` on the `iris`
  service; requests-based analyzers (HTTP/download + threat-feed IP resolution) now retry
  through `request_with_doh_fallback`; Bulk Scan retries a row once (1.2s backoff, reusing
  the concurrency slot) before marking it ERROR. WHOIS/DNS keeps its native resolver — its
  "does not resolve" finding is an intentional signal — and is covered by the compose `dns:`
  resolvers at the system-resolver level. 6 new unit tests (`test_dns_doh_fallback.py`).
- **More scan-speed headroom** (after the latest perf pass): the deferred Download analyzer
  runs serially on the main thread *after* the whole parallel phase finishes, but the main
  thread sits idle from when the browser analyzers end until the slowest thread analyzer
  (WHOIS/DNS) returns — Download could run in that window. Also, the landing page is
  navigated/screenshotted twice (overlapped `capture_screenshot` → `screenshot_path` for the
  API, plus `capture_multi_screenshots` → `multi_screenshots.initial` for the UI); consolidating
  could save ~2s but has two consumers. Both are bigger refactors, parked.
- Bulk "Import from feed" button is **online-only**; expose the `--all`/offline toggle in the UI.
- Decide whether a **critical classification** (e.g. ClickFix) should nudge the verdict
  (currently orthogonal by design).
- Larger roadmap (parked): cloud/isolated browser pool + egress proxy (OPSEC), feed-result
  caching, analyzer unit tests, collapse the two render paths, metrics/SLOs, SOAR/case-mgmt
  push, multi-tenancy, ML classifier.

## Conventions
- Match surrounding code; PEP 8, type hints, docstrings (per user's global CLAUDE.md).
- End commit messages with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Verify changes live where feasible (dev server / container + Playwright screenshots) and
  keep both `results.html` render paths in sync.
- Never commit `config/local.yaml` or `screenshots/iris.db` (both gitignored).
