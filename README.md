<div align="center">

# SOC Box — The SOC Analyst's Toolbox

**The containerized SOC analyst toolbox — URL analysis, phishing detection, and threat assessment.**

[![Docker Image](https://img.shields.io/badge/ghcr.io-fredzirbel%2Fsocbox-blue?logo=docker)](https://ghcr.io/fredzirbel/socbox)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

SOC Box is a containerized toolbox for SOC analysts — a homepage hub of self-hosted apps for the pivots analysts make all day. Its flagship URL scanner detonates suspect links across 8 security dimensions simultaneously — lexical analysis, SSL certificates, WHOIS records, HTTP headers, page content, link discovery, file downloads, and threat intelligence feeds — and produces a weighted risk score with an interactive results dashboard streamed in real time. Alongside it: multi-source IP enrichment, a KQL hunting-query generator, and more tools on the way.

> **Formerly IRIS.** This project was renamed from IRIS (Intelligent Risk Inspection System) as its scope grew beyond URL analysis. Old GitHub links redirect automatically; container images now publish as `ghcr.io/fredzirbel/socbox`.

## Features

### URL & Phishing Analysis

- **8 Security Analyzers** running concurrently across URL, network, and content layers
- **3-Tier Scoring** — Safe / Uncertain / Malicious with weighted confidence percentages
- **Real-time SSE Streaming** — results appear progressively as each analyzer completes
- **In-Browser CAPTCHA Solving** — pauses on an un-automatable CAPTCHA and surfaces the live detonation browser to the analyst (CLI on-screen, or transparent self-hosted noVNC takeover in the web UI); clearance is captured once and replayed across the scan
- **Bulk Scanning** — scan many URLs concurrently (up to 8 parallel workers, default 5) with progress tracking
- **Playwright-based Screenshot Capture** with URL banner overlay and redirect detection
- **Active Link Discovery** — clicks sign-in/login buttons to find hidden credential harvesters
- **File Download Analysis** — detects automatic downloads, computes SHA-1 and SHA-256, queries VirusTotal
- **Threat Feed Integration** — VirusTotal (severity-aware detection scaling), Google Safe Browsing, AbuseIPDB
- **Clickable Threat Labels** — VT threat labels link to OSINT search for malware family research
- **OSINT Link Panel** — one-click links to VirusTotal (including redirect hops), URLScan.io, AbuseIPDB, and more
- **Cloudflare Bypass** — navigates past Cloudflare phishing interstitials for analysis
- **DNS-over-HTTPS Fallback** — resolves domains blocked by ISP/router DNS filters

### Analyst Tools

- **IP Enrichment** (`/tools/ip`) — one paste, concurrent reputation/geo/ASN lookups across VirusTotal, AbuseIPDB, IPinfo, and an optional local MaxMind GeoLite2 database, with copyable OSINT pivot links; sources degrade gracefully when unconfigured
- **KQL Generator** (`/tools/kql`) — turns any indicator (IP, domain, URL, file hash, email) into ready-to-paste Microsoft Defender XDR / Sentinel Advanced Hunting queries via deterministic templates
- **Per-Scan Hunt Queries** — every URL scan can emit KQL tailored to its findings: URL-click and email-delivery pivots, anomalous sign-in queries for phishing verdicts, and file-hash/hosting pivots for malicious downloads
- **"Copy Claude prompt" pattern** — for reasoning steps (bespoke hunts, verdicts), SOC Box stays deterministic and instead assembles a purpose-built prompt the analyst pastes into their own Claude seat; no external LLM calls from the platform
- **Roadmap** — Command Deobfuscator (nested base64/hex/gzip/char-code unwinding with ATT&CK technique tagging) and Email Header Analyzer (SPF/DKIM/DMARC, hop chain, spoofing checks) are next

### Platform

- **Authenticated & Hardened** — OIDC SSO for analysts + bearer service tokens for the agent, an SSRF guard, and rate limiting (see [Security](#security--hardening))
- **REST API** — synchronous and async JSON endpoints for SOAR playbook integration
- **Defanged IOC Display** — all URLs rendered as `hxxps://example[.]com` for safe sharing
- **Copy Report** — one-click clipboard export of full reports; per-field copy buttons for IOCs
- **Dark-themed Web UI** with collapsible sections and mobile-responsive layout
- **CLI Mode** for scripted/automated scanning

## Quick Start

### Docker (Recommended)

Pull and run the pre-built image:

```bash
docker run -p 8080:8000 --shm-size=2g ghcr.io/fredzirbel/socbox:latest
```

Open **http://localhost:8080** and paste a URL to scan.

### Docker Compose (with API Keys)

For full threat feed integration:

```bash
git clone https://github.com/fredzirbel/SOCBox.git
cd SOCBox
cp config/default.yaml config/local.yaml
```

Edit `config/local.yaml` with your API keys, then:

```bash
docker compose up --build
```

### Environment Variables

Alternatively, pass API keys as environment variables:

```bash
docker run -p 8080:8000 --shm-size=2g \
  -e VIRUSTOTAL_API_KEY=your_key \
  -e GOOGLE_SAFEBROWSING_API_KEY=your_key \
  -e ABUSEIPDB_API_KEY=your_key \
  ghcr.io/fredzirbel/socbox:latest
```

## Analyzers

| Analyzer | Weight | What It Checks |
|----------|--------|----------------|
| **URL Lexical Analysis** | 20 | Domain age indicators, typosquatting (Levenshtein distance), suspicious TLDs, URL shorteners, excessive subdomains, IP-based URLs, homoglyph characters |
| **WHOIS/DNS Inspection** | 15 | Domain registration age, registrar privacy/proxy use, whether the domain resolves (NXDOMAIN), missing MX (email) records |
| **HTTP Response Analysis** | 15 | Redirect chains, missing security headers (CSP, X-Frame-Options), suspicious status codes, cross-domain redirects |
| **Page Content Analysis** | 15 | Login form detection, brand impersonation keywords, hidden form fields, credential harvesting patterns |
| **Download Analysis** | 15 | Detects auto-downloads, flags suspicious file extensions, computes SHA-1 and SHA-256, queries VirusTotal for file reputation |
| **SSL/TLS Certificate** | 10 | Free-CA certificate on a brand-impersonating domain, very recently issued certs, SAN/hostname mismatch, expired certificates (cert parsed from DER so it works even when validation would fail) |
| **Link Discovery** | 10 | Clicks auth-related buttons on the page, inspects destination for credential forms, cross-domain redirects, and brand spoofing |
| **Threat Feed Integration** | 0 | Queries VirusTotal, Google Safe Browsing, and AbuseIPDB for findings display; feed impact is scored via blended threat-feed signal below |

## Scoring

SOC Box uses a **dual-signal scoring engine** that blends analyzer scores (45%) with threat feed results (55%) into a final 0–100 risk score. Feed scoring is **severity-aware** — a URL flagged by 20 VirusTotal engines scores far higher than one with 3 detections, rather than treating all matches equally.

Threat feeds contribute once through the blended feed signal (not double-counted through analyzer weighting).

| Score | Category | Meaning |
|-------|----------|---------|
| 0–25 | **Safe** | No significant indicators detected |
| 26–59 | **Uncertain** | Some anomalies — investigate further before taking action |
| 60–100 | **Malicious** | Strong phishing indicators or confirmed by threat intelligence |

Special categories exist for file download threats: **Malicious File Download** and **Suspicious File Download**.

**Confidence** is tuned for SOC analyst clarity: Malicious verdicts report **100% confidence**; a **Safe** verdict scales with how much evidence was gathered (a full scan → 100%, but a thin scan where the site was unreachable and only lexical analysis ran → lower, so a green verdict built on sparse data is visibly less certain); **Uncertain** scales **30–80%** on a U-curve (higher near decision boundaries, lowest in the ambiguous middle).

**Feed floor enforcement** prevents strong VirusTotal signals from being diluted into "Safe" when other feeds (GSB, AbuseIPDB) haven't indexed the campaign yet. For example, 10+ VT detections enforce a minimum composite score of 65 (Malicious).

Threat feed matches are weighted individually (VirusTotal 40%, Google Safe Browsing 35%, AbuseIPDB 25%) and blended with analyzer evidence.

## Security & Hardening

SOC Box fetches attacker-controlled URLs server-side and renders their content back to analysts, so it is built to sit safely inside a SOC:

- **Authentication** — analysts sign in via **OIDC SSO** (Azure AD / Okta); the AI triage agent / SOAR authenticates with **bearer service tokens**. A fail-closed, SSE-safe ASGI middleware gates every page, `/api/*`, `/stream`, and `/screenshots`. `auth.mode` ∈ {`oidc`, `dev`, `disabled`}; `dev` auto-login requires `SOCBOX_AUTH_DEV=1`.
- **SSRF guard** — every scan target is resolved and rejected if it lands on a private / loopback / link-local / cloud-metadata address. The DoH resolution fallback and the async webhook `callback_url` are held to the same check, so neither can be used to reach internal services.
- **Rate limiting** — scan endpoints are capped per service token / client IP.
- **XSS-safe reporting** — the analyst-facing report is rendered safely even when the scanned page's own content (filenames, page text, evidence) is hostile.
- **Secure headers** — CSP, `X-Frame-Options`, `nosniff`, and `Referrer-Policy` on every response.
- **Secrets via env only** — `SOCBOX_SESSION_SECRET`, `SOCBOX_OIDC_CLIENT_SECRET`, `SOCBOX_API_TOKENS`; never committed.
- **CI** — `ruff`, `bandit`, `pip-audit`, and `gitleaks` run on every change.

## Architecture

```
                 ┌──────────────────────────────────────────┐
                 │              FastAPI Web UI              │
                 │         (SSE streaming results)          │
                 └─────────────────────┬────────────────────┘
                                       │
                 ┌─────────────────────▼────────────────────┐
                 │          Scanner Orchestrator            │
                 │    (ThreadPoolExecutor + Playwright)     │
                 └─────────────────────┬────────────────────┘
                                       │
                   ┌───────────────────┼───────────────────┐
                   │                   │                   │
          ┌────────▼────────┐ ┌────────▼────────┐ ┌────────▼────────┐
          │  Thread Pool    │ │  Playwright     │ │  Deferred       │
          │  (concurrent)   │ │  (sequential)   │ │  (post-browser) │
          ├─────────────────┤ ├─────────────────┤ ├─────────────────┤
          │ URL Lexical     │ │ Page Content    │ │ Download        │
          │ WHOIS/DNS       │ │ Link Discovery  │ │  Analysis       │
          │ SSL/TLS         │ │                 │ │                 │
          │ HTTP Response   │ │ Screenshot      │ │                 │
          │ Threat Feeds    │ │  Capture        │ │                 │
          └─────────────────┘ └─────────────────┘ └─────────────────┘
```

- **Thread pool analyzers** run concurrently (network I/O bound)
- **Playwright analyzers** run sequentially on a dedicated thread (browser-bound)
- **Deferred analyzers** get a browser fallback pass after the thread pool finishes
- **Thread-local browser pool** — each scan worker thread (up to 8, default 5) maintains its own persistent Playwright/Chromium instance, enabling concurrent scans while avoiding greenlet conflicts
- **Screenshots** are captured immediately after page content analysis while the page is fresh

## OSINT Links

Each scan report includes one-click links to external tools for deeper investigation:

- **VirusTotal (URL)** — URL reputation lookup
- **VirusTotal (Domain)** — domain reputation and history
- **VirusTotal (Redirect Hops)** — individual URL and domain lookups for each unique redirect in the chain
- **Google Transparency Report** — Safe Browsing status
- **URLScan.io** — live site scan
- **who.is** — WHOIS registration lookup
- **AbuseIPDB** — IP abuse history (when IP is resolved)

## Configuration

The default configuration (`config/default.yaml`) works out of the box for basic scanning. For threat feed integration, create `config/local.yaml`:

```yaml
api_keys:
  virustotal: "your-api-key"
  google_safebrowsing: "your-api-key"
  abuseipdb: "your-api-key"
```

`config/local.yaml` is gitignored. Keep real keys only in local/dev secret stores or environment variables.

### Configuration Options

| Section | Key | Description |
|---------|-----|-------------|
| `api_keys` | `virustotal`, `google_safebrowsing`, `abuseipdb` | API keys for threat feed integration |
| `scoring.weights` | `url_lexical`, `whois_dns`, `ssl_tls`, `http_response`, `page_content`, `link_discovery`, `download`, `threat_feeds` | Analyzer weight distribution (must sum to 100) |
| `scoring.thresholds` | `safe`, `malicious` | Score boundaries for 3-tier risk categories |
| `scoring.blend` | `analyzer_weight`, `feed_weight` | Relative weight of analyzers vs. threat feeds (must sum to 1.0) |
| `scoring.feed_weights` | `VirusTotal`, `Google Safe Browsing`, `AbuseIPDB` | Per-feed weight distribution for blended scoring |
| `brands` | List of FQDNs | Brand names to check for impersonation/typosquatting |
| `suspicious_tlds` | List of TLDs | TLDs commonly used in phishing (e.g., `.xyz`, `.top`) |
| `url_shorteners` | List of domains | Known URL shortener services |
| `abused_hosting_domains` | List of domains | CDN/hosting platforms commonly abused for payload delivery |
| `suspicious_extensions` | List of extensions | File extensions flagged as potentially malicious |

## CLI Usage

SOC Box also supports command-line scanning:

```bash
# Basic scan
socbox https://example.com

# Verbose output with all findings
socbox -v https://suspicious-site.xyz

# Passive-only mode (lexical-only; no network/browser analyzers)
socbox --no-active https://example.com

# Custom config file
socbox -c config/local.yaml https://example.com
```

### Importing test URLs from threat feeds

Pull recent **live** malicious URLs from public feeds (via their official APIs —
no scraping) to feed into a scan or the Bulk Scan box:

```bash
# 20 recent online malware URLs from URLhaus (needs api_keys.urlhaus)
socbox-feeds --source urlhaus --limit 20

# Filter by URLhaus tag, e.g. ClearFake / Mozi
socbox-feeds --source urlhaus --tag ClearFake --limit 10

# OpenPhish phishing feed (no key required); save to a file
socbox-feeds --source openphish --limit 30 --output urls.txt
```

URLhaus requires a free abuse.ch Auth-Key (https://auth.abuse.ch) in
`api_keys.urlhaus` (config/local.yaml) or the `URLHAUS_AUTH_KEY` env var. Output
is one URL per line on stdout — treat it as live malicious infrastructure.

## API Endpoints

### Web UI

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Home page with URL input form |
| `GET` | `/bulk` | Bulk scan page (accepts `?id=` to restore a cached session) |
| `GET` | `/results/{scan_id}` | Full results page (static mode) |
| `GET` | `/results/{scan_id}?stream=1` | Results page with live SSE streaming |
| `GET` | `/stream/{scan_id}` | SSE event stream for real-time results |
| `GET` | `/tools/ip` | IP enrichment tool |
| `GET` | `/tools/kql` | KQL hunting-query generator |

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start an async scan — returns `{"scan_id": "..."}` for SSE streaming |
| `POST` | `/api/scan/sync` | Run a synchronous scan — blocks and returns complete JSON results |
| `GET` | `/api/results/{scan_id}` | Retrieve completed scan results as JSON (includes defanged URLs) |
| `POST` | `/api/hash-lookup` | Manual SHA-256 hash lookup via VirusTotal |
| `POST` | `/api/bulk` | Create or update a bulk scan session |
| `GET` | `/api/bulk/{bulk_id}` | Retrieve a cached bulk scan session |
| `POST` | `/api/enrich/ip` | Multi-source IP enrichment (VirusTotal, AbuseIPDB, IPinfo, optional GeoLite2) |
| `POST` | `/api/tools/kql` | Generate Defender XDR / Sentinel KQL from pasted indicators |
| `GET` | `/api/kql/{scan_id}` | KQL hunting queries tailored to a completed scan's findings |
| `GET` | `/api/feeds/import` | Pull live malicious test URLs from URLhaus / OpenPhish |

### v1 TAP API (agent / SOAR)

Stable, machine-friendly URL actions — a SlashNext-style TAP contract. Every
response includes the **final landing URL**. Each action accepts `{"url": ...}`
(runs a scan) or `?scan_id=` (reuses an existing scan).

| Method | Endpoint | Returns |
|--------|----------|---------|
| `POST` | `/api/v1/url/scan` | Full result: verdict, `suggested_disposition`, score, `final_url`, `text`, `screenshot_url`, classifications |
| `POST` | `/api/v1/url/text` | `{final_url, text}` — visible text of the final landing page |
| `POST` | `/api/v1/url/screenshot` | `{final_url, screenshot_url}` |
| `POST` | `/api/v1/url/threat-intel` | `{final_url, verdict, suggested_disposition, score, confidence, classifications}` |
| `POST` | `/api/v1/scan/{id}/disposition` | Record analyst disposition `{"disposition": "TP"\|"BTP"\|"FP", "analyst", "note"}` |
| `POST` | `/api/v1/scan/async` | Queue a scan: `{url, callback_url?}` → `{job_id}`; POSTs the result to the callback on completion |
| `GET`  | `/api/v1/scan/{job_id}` | Poll an async job's status/result |

The machine **verdict** (Safe/Uncertain/Malicious) maps to a `suggested_disposition`
(TP / needs review / FP candidate); analysts confirm the real TP/BTP/FP, which
persists (SQLite) for accuracy reporting. Completion webhooks are configured via
`notifications.webhook_url` (per-request `callback_url` overrides).

```bash
# Full TAP result (final_url + text + verdict)
curl -X POST http://localhost:8080/api/v1/url/scan \
  -H "Content-Type: application/json" -d '{"url":"https://suspicious-site.xyz"}'

# Fire-and-forget with a completion webhook
curl -X POST http://localhost:8080/api/v1/scan/async \
  -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious-site.xyz","callback_url":"https://soar.internal/socbox-hook"}'
```

### SOAR Integration Example

```bash
# Synchronous scan — blocks until complete (set timeout ≥ 120s)
curl -X POST http://localhost:8080/api/scan/sync \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.xyz"}'

# Retrieve a previous scan
curl http://localhost:8080/api/results/abc123def456
```

## Development

### Local Setup

```bash
git clone https://github.com/fredzirbel/SOCBox.git
cd SOCBox
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
playwright install chromium
pre-commit install
```

### Running Tests

```bash
pytest
```

### Linting

```bash
ruff check src/
```

### Secret Scanning

```bash
pre-commit run --all-files
```

## Tech Stack

- **Backend:** Python 3.11, FastAPI, Uvicorn
- **Auth & Crypto:** Authlib (OIDC), itsdangerous (signed sessions), cryptography (certificate parsing), slowapi (rate limiting)
- **Browser Automation:** Playwright (Chromium)
- **Frontend:** Jinja2 templates, vanilla JS, CSS (dark theme)
- **Streaming:** Server-Sent Events (SSE)
- **Container:** Docker, Docker Compose
- **CI/CD:** GitHub Actions (auto-publish to GHCR)

## License

MIT
