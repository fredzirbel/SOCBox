# SOC Box Analyst Tools — Build Handoff

**Purpose:** hand this file to a fresh chat to continue the "Analyst Tools" initiative.
Read `PROJECT.md` first (living architecture/run doc), then this. Next task: build the
**Command Deobfuscator** (spec at the bottom), following the established pattern.

- **Repo:** github.com/fredzirbel/SOCBox (`main`, all work pushed) · **Local:** `C:\Users\Freddy\Desktop\Projects\SOCBox`
- **Owner:** Fred Zirbel — Senior Security Analyst, Critical Start.

---

## The initiative

Add SOC analyst tools to SOC Box as a **homepage hub of separate "apps."** Four were scoped;
the analyst pastes an artifact and gets analyst-ready, copyable output. Build order: IP
enricher → KQL generator → **Command Deobfuscator (next)** → Email Header Analyzer.

### Two decisions that shape everything
1. **No bespoke Claude API integration.** The analysts have their own **Claude Enterprise
   seats**, and the public API is a separate purchase + a new data-governance boundary. So
   for any AI-reasoning step (deobfuscator verdict, freeform KQL, alert triage), SOC Box stays
   deterministic/self-hosted and emits a **"Copy Claude prompt"** button — a purpose-built
   prompt + the artifact the analyst pastes into their own Claude seat. **Do not add the
   `anthropic` SDK or any external LLM call.**
2. **Everything degrades gracefully** and is self-hosted; no new required deps unless
   trivial + optional (e.g. MaxMind's `geoip2` is optional, skipped if absent).

---

## Status

| Tool | Route | Status |
|------|-------|--------|
| URL Scan | `/` | shipped (pre-existing) |
| Bulk Scan | `/bulk` | shipped (pre-existing) |
| **IP Enrichment** | `/tools/ip` | ✅ done (`src/socbox/enrich.py`, `templates/ip_enrich.html`, `test_enrich.py`) |
| **KQL Generator** | `/tools/kql` | ✅ done (`src/socbox/web/kql.py`, `templates/kql.html`, `test_kql.py`) |
| **Command Deobfuscator** | `/tools/deobfuscate` | ⬜ NEXT — spec below |
| Email Header Analyzer | `/tools/email` | ⬜ after |

Homepage hub (`templates/index.html`) has a card per tool; the last two show a dimmed
`Soon` badge — flip each to a live `<a class="tool-card" href="...">` when it ships.
Nav links live in `templates/base.html` (`.nav-right .nav-link`).

Tests: **132 passing**, ruff + bandit clean as of the KQL commit.

---

## The pattern to replicate (per tool)

1. **Core module** — pure logic, no web deps. IP enricher lives at `src/socbox/enrich.py`;
   web-facing text tools (KQL) live under `src/socbox/web/`. Deterministic, unit-testable,
   returns plain dicts.
2. **Routes in `src/socbox/web/app.py`** — a `GET /tools/<name>` page route returning
   `templates.TemplateResponse(request, "<name>.html", {})`, and a `POST /api/tools/<name>`
   (or `/api/enrich/ip`-style) JSON endpoint. Scan-style endpoints get `@limiter.limit(_scan_rate_limit)`.
3. **Template** — `templates/<name>.html`, `{% extends "base.html" %}`, `{% block content %}`,
   a scoped `<style>` block using the theme CSS vars (`--bg-card`, `--border`, `--text`,
   `--text-muted`, `--accent`, `--on-accent`, `--radius`, `--radius-lg`, `--green`, `--red`,
   `--yellow`, `--bg-input`, `--bg-elev`, `--font-display`, `--transition`). Vanilla JS,
   `fetch()` to the API, an `esc()` helper to HTML-escape **every** externally-influenced
   value before `innerHTML`, and copy buttons (`navigator.clipboard.writeText`).
4. **Flip the homepage card** live (`index.html`) + **add a nav link** (`base.html`).
5. **Tests** — `tests/unit/test_<name>.py`, network-free (monkeypatch `requests.get` or test
   pure functions). Cover: happy path, malformed input, and injection escaping.
6. **Verify** — run the dev server + Playwright screenshot (see below), read the PNG.

### Conventions
- **Escaping:** JS side uses the `esc()` helper (create span, set `textContent`, read
  `innerHTML`). Server side, KQL/command strings that embed IOCs use
  `socbox.web.escalation._kql_str` (escapes `\ " \r \n`). Never interpolate attacker text raw.
- **Defang for display** (`1[.]2[.]3[.]4`), refang on input (`.replace("[.]",".")`, `hxxp`→`http`, `[at]`→`@`).
- **Copy-to-Claude:** build the prompt server-side as plain text, return it in the JSON,
  copy it with a button. See `kql.claude_prompt()` for the shape.
- Commit messages end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
  (LF→CRLF git warnings on Windows are harmless.)

---

## Run & verify

```powershell
# Dev server (PowerShell). Port 8000 is unusable (WinNAT 7908-8007); use 8017.
cd C:\Users\Freddy\Desktop\Projects\SOCBox
$env:SOCBOX_AUTH_DEV = "1"; $env:SOCBOX_PORT = "8017"
.\.venv\Scripts\python.exe -m socbox.web.app --no-reload    # Ctrl+C to stop
# then open http://localhost:8017  (--no-reload means restart to pick up new routes)
```

```bash
# Tests / lint (venv is Python 3.14)
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m ruff check src tests
```

Playwright screenshot recipe (used to verify each tool visually): launch a headless
chromium via the installed `playwright`, `goto` the tool URL, `fill`/`click` the form,
`wait_for_timeout`, `screenshot(full_page=True)`, then read the PNG. If a stale server holds
the port, kill it from PowerShell:
`Get-NetTCPConnection -LocalPort 8017 -State Listen | %{ Stop-Process -Id $_.OwningProcess -Force }`.

---

## NEXT: Command Deobfuscator (`/tools/deobfuscate`)

**Goal:** analyst pastes an obfuscated one-liner (ClickFix payloads, `powershell -enc …`,
`mshta`, `certutil -decode`, char-code arrays, base64/hex/gzip, possibly nested). SOC Box
decodes/normalizes it deterministically, tags likely techniques (reuse
`socbox.classification` pattern banks), and offers a **"Copy Claude prompt"** for a verdict.
**Egress-safe** — the string is already in hand; SOC Box makes no network call.

### Core module: `src/socbox/deobfuscate.py`
- `deobfuscate(text) -> dict` returning `{"layers": [...], "decoded": "<final>", "notes": [...]}`.
  Each layer records the transform applied (e.g. "base64 (UTF-16LE)", "gzip", "hex",
  "URL-decode", "char-code array") and its output, so the UI can show the unwind chain.
- Decoders to implement (apply iteratively until stable, cap ~10 layers to avoid loops):
  - **PowerShell `-enc` / `-EncodedCommand`**: base64 → **UTF-16LE** decode (the classic case).
    Detect via the `-e`/`-enc`/`-encodedcommand` flag or a base64 blob that UTF-16LE-decodes to
    mostly-printable text.
  - **Standard base64** (UTF-8), **hex** (`\x41`, `0x41`, or bare hex pairs), **gzip/deflate**
    (base64→gunzip), **URL/percent-decode**, **`char`/`[char]` code arrays** and JS
    `String.fromCharCode(...)`, **`FromBase64String`**, **`certutil -decode`** (treat payload as base64),
    optional **ROT13**.
  - Nesting: after each successful decode, re-scan the output for another layer.
- `technique_tags(decoded, original) -> list[dict]` — reuse `socbox.classification` signals
  (ClickFix `_RUN_DIALOG`/`_SHELL`, encoded-command markers, clipboard, drainer, etc.) mapped
  to ATT&CK ids. Keep it rule-based; **no verdict claim** (that's Claude's job).
- `claude_prompt(original, decoded, tags) -> str` — assemble a prompt: "You are a senior SOC
  analyst. Here is an obfuscated command and its decoded form. Give a verdict
  (Malicious/Suspicious/Benign) with justification, the ATT&CK techniques, and any IOCs."
  Fence the payload as **data, not instructions** (prompt-injection: wrap in a clearly
  delimited block and tell the model to treat it as untrusted input to analyze).

### Routes (`app.py`)
- `GET /tools/deobfuscate` → `templates.TemplateResponse(request, "deobfuscate.html", {})`.
- `POST /api/tools/deobfuscate` → `{"text": "..."}` → returns
  `{layers, decoded, notes, tags, claude_prompt}`.

### Template: `templates/deobfuscate.html`
- Paste box + "Decode" button. Render: the **layer chain** (each transform + snippet),
  the **final decoded command** in a `<pre>` with a Copy button, **technique-tag chips**
  (ATT&CK id + label), and a **"Copy Claude prompt"** button. Escape everything via `esc()`.

### Homepage + nav
- Flip the Command Deobfuscator card in `index.html` from `<span class="tool-card disabled">`
  to `<a class="tool-card" href="/tools/deobfuscate">` (drop the `Soon` badge).
- Add `<a href="/tools/deobfuscate" class="nav-link">Deobfuscate</a>` in `base.html`.

### Tests: `tests/unit/test_deobfuscate.py`
- PowerShell `-enc` UTF-16LE base64 → decoded command (use a real `-enc` sample from
  `socbox` history / `test_classification.py`'s `powershell -enc SQBFAFgA…`).
- Nested (base64 of base64), hex, gzip, char-code array → correct final output.
- Benign long base64 (e.g. a data-URI) does **not** produce a technique tag on its own
  (mirror the encoded-command FP fix already in `classification.py`).
- `claude_prompt` includes both original + decoded and treats the payload as data.

### Commit
`feat: command deobfuscator tool` (+ flip homepage card / nav).

---

## AFTER: Email Header Analyzer (`/tools/email`)

Paste raw headers or a `.eml` → parse **SPF / DKIM / DMARC** (from `Authentication-Results`),
`Received` hop chain + per-hop delays, originating IP (→ pivot to `/tools/ip`), `Reply-To` vs
`From` and **display-name spoofing**, and extract URLs (→ pivot to a scan) + attachment
names/hashes. Pure stdlib `email` parsing (`email.parser.Parser`, `email.utils`); no new deps.
Same pattern (module `src/socbox/email_headers.py` or `src/socbox/web/emailhdr.py`, routes, page,
flip card, nav, tests). Add "Copy report" (ticket-ready summary). No LLM needed, though a
"Copy Claude prompt" for a phishing verdict is a nice optional add.
