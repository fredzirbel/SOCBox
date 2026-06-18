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
  range 7908–8007). `restart: unless-stopped`.
- **Dev server:** `IRIS_PORT=8015 .venv/Scripts/python.exe -m iris.web.app --no-reload`
- **Tests/lint:** `.venv/Scripts/python.exe -m pytest -q` (48 passing) · `... -m ruff check src tests`
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
- `src/iris/browser.py` — Playwright launch, Cloudflare bypass, **interactive CAPTCHA
  solve**, human-like behavior, `detect_interactive_captcha`, `set_action_notifier`,
  per-URL DNS via `--host-resolver-rules` (DoH fallback — **browser only**).
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

## Config & secrets
- `config/default.yaml` (committed, empty slots) / `config/local.yaml` (**gitignored**, real keys).
- Keys present in local.yaml: virustotal, google_safebrowsing, abuseipdb, **urlhaus**.
- `notifications.webhook_url` (+ `webhook_timeout`) for async completion webhooks.
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

## Open / pending (next-session candidates, roughly prioritized)
- **#6 API auth** — every `/api/*` endpoint is currently **unauthenticated** (service tokens
  for the agent + SSO for the UI). Needed before exposing to the agent on the network.
- **DNS robustness** (diagnosed but not fixed): transient *container* DNS failures errored
  3 bulk rows. Quick win: add `dns: [1.1.1.1, 8.8.8.8]` to the `iris` service in
  `docker-compose.yml`. Medium: route the requests-based analyzers (HTTP/feeds/WHOIS/
  download) through the DoH fallback (currently DoH only covers the browser). Bulk: retry
  once on SSE error before marking a row ERROR.
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
