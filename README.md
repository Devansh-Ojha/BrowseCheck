# BrowseCheck

Security layer for browser agents. **Prevention, not observation:**
every proposed agent action is gated by a hook pipeline *before* it executes
(`observe -> hooks -> act`). Runs on Browserbase via Stagehand; threats surface
live on a dashboard with a before/after scorecard.

## Quickstart
```bash
pip install -r requirements.txt
cp .env.example .env          # fill ANTHROPIC_API_KEY (+ BROWSERBASE_* for the demo)
uvicorn browsecheck.server.app:app --reload --port 8000
# open http://localhost:8000  ->  click "Run demo (synthetic)"
```
The synthetic run streams scripted events through the real bus to the dashboard —
no browser, LLM, or red-team URL required — so the UI/scorecard are demoable now.

## Layout
```
browsecheck/
  contracts.py      FROZEN hook + event contracts (shared)
  config.py         env / LOCAL<->BROWSERBASE seam
  llm/provider.py   Anthropic wrapper: classify() + respond()  [P1]
  browser/          Playwright/CDP executor + live-view URL     [P1]
  controlloop/      Claude tool-use -> hooks -> act -> log       [P1]
  hooks/            base, registry, factory (shared);
                      prompt_injection, intent_drift  HERO      [P1]
                      download_inspect, credential_phish, cert_ssl [P2]
  events/           bus + Memory/SSE/Sentry sinks               [P2]
  server/app.py     FastAPI: SSE + run controls + scorecard     [P2]
  scorecard/        before/after tally                          [P2]
  demo/synthetic.py scripted events for UI dev                  [P2]
  tasks/demo_task.py user task + 5-site list (shared)
dashboard/index.html  minimalist live dashboard                 [P2]
```

See **`TASKS.md`** for the full two-engineer split and ordered build sequence.
