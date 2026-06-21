# BrowseCheck

Runtime security layer for AI browser agents. Every action the agent proposes is inspected by a hook pipeline **before** it executes — if anything looks malicious, it's blocked before the browser ever touches it.

## How it works

```
user task + sites
       │
  control loop          for each agent step:
  observe → hooks → act   1. observe the proposed action
       │                   2. run hook pipeline (LLM + deterministic)
       ▼                   3. BLOCK or allow — never skip step 2
   SecurityEvent
       │
  ┌────┴──────────────┐
  MemorySink  SSESink  SentrySink
  (scorecard) (dashboard) (alerts)
```

**Hooks:**
- `prompt_injection` — detects hidden/adversarial instructions in page content
- `intent_drift` — blocks actions outside the user's original task
- `credential_phish` — flags password forms on non-auth domains
- `download_inspect` — blocks executables and suspicious downloads
- `cert_ssl` — blocks non-HTTPS pages

## Quickstart

```bash
pip install -r requirements.txt
python -m playwright install chromium

cp .env.example .env   # fill in keys (see below)

uvicorn browsecheck.server.app:app --reload --port 8000
```

Open **http://localhost:8000** and click **"Synthetic"** — no API keys needed. Scripted events stream through the real pipeline to the dashboard so the UI and scorecard are fully exercisable without a browser or LLM.

## Environment variables

```bash
# Required for live agent run
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-6   # default

# Required for Browserbase cloud browser
ENV=BROWSERBASE
BROWSERBASE_API_KEY=bb_live_...
BROWSERBASE_PROJECT_ID=...

# Optional: point at the red-team malicious site
REDTEAM_URL=https://...

# Optional: Sentry error tracking
SENTRY_DSN=https://...@sentry.io/...
```

Leave `ENV=LOCAL` to run with a local headless Chromium (no Browserbase keys needed).

## Verify everything works

```bash
python verify.py
```

Runs 4 levels — skips cleanly if a key is missing:
- **L0** deterministic hooks (no keys)
- **L1** LLM hero hooks (`ANTHROPIC_API_KEY`)
- **L2** full agent loop on a local injection fixture
- **L3** Browserbase CDP connect (`ENV=BROWSERBASE`)

## Project layout

```
browsecheck/
  contracts.py          frozen event + hook types (shared)
  config.py             env / LOCAL↔BROWSERBASE seam
  llm/provider.py       Anthropic wrapper
  browser/              Playwright/CDP executor + live-view URL
  controlloop/          Claude tool-use loop: gate every action
  hooks/
    prompt_injection.py LLM — hidden instructions
    intent_drift.py     LLM — out-of-scope actions
    credential_phish.py deterministic — phishing forms
    download_inspect.py deterministic — malicious downloads
    cert_ssl.py         deterministic — non-HTTPS / bad certs
  events/               event bus + Memory / SSE / Sentry sinks
  server/app.py         FastAPI: dashboard, SSE, run controls
  scorecard/            before/after block tally
  demo/synthetic.py     scripted events for UI dev (no browser)
  tasks/demo_task.py    user task + site list
dashboard/index.html    live dashboard (vanilla JS + Tailwind)
```
