# Development Guide — BrowseCheck

## Quick Start (Person 2)

```bash
# Setup
pip install -r requirements.txt
cp .env.example .env

# Run tests
python test_hooks.py           # Unit: 3 deterministic hooks
python test_dashboard.py       # Event handling: all 8 event kinds
python test_integration.py     # E2E: sinks, synthetic, registry

# Run server
uvicorn browsecheck.server.app:app --reload --port 8000

# In another terminal: test the demo
curl -X POST http://localhost:8000/run/synthetic
sleep 8 && curl http://localhost:8000/scorecard | jq .

# Open dashboard
open http://localhost:8000
```

## Project Layout

```
browsecheck/
├── contracts.py        ✓ Frozen API (shared with P1)
├── config.py          ✓ ENV management
├── events/
│   ├── bus.py         ✓ Pub/sub + sink registration
│   └── sinks.py       ✓ Memory / SSE / Sentry
├── hooks/
│   ├── base.py        ✓ SecurityHook interface
│   ├── registry.py    ✓ Registry + pipeline (P1 maintains)
│   ├── factory.py     ✓ Hook assembly
│   ├── download_inspect.py    ✓ P2 deterministic
│   ├── credential_phish.py    ✓ P2 deterministic
│   ├── cert_ssl.py            ✓ P2 deterministic
│   ├── prompt_injection.py    ✓ P1 LLM-backed hero
│   └── intent_drift.py        ✓ P1 LLM-backed hero
├── server/
│   └── app.py         ✓ FastAPI (GET/, POST /run/synthetic, GET /events, GET /scorecard, etc)
├── demo/
│   └── synthetic.py   ✓ Scripted run (for dashboard dev, no keys needed)
├── scorecard/
│   └── runner.py      ⏳ Needs P1's BrowserSession + control loop
├── browser/           📍 P1 owns
│   ├── session.py     ⏳ BrowserSession (LOCAL / BROWSERBASE)
│   └── replay.py      ⏳ Live-view URL for dashboard iframe
├── controlloop/       📍 P1 owns
│   └── loop.py        ⏳ observe → hooks → act → publish
└── llm/               📍 P1 maintains
    └── provider.py    ✓ Anthropic wrapper (tool-use for structured output)
```

## API Contracts

### SecurityEvent (frozen)
Single event type, consumed by dashboard + scorecard + Sentry:
```python
SecurityEvent(
    id: str,
    ts: float,
    session_id: str,
    run_mode: "hooks-on" | "hooks-off",
    step_index: int,
    site: { url, domain, label },
    kind: "navigate" | "observe" | "hook-pass" | "hook-block" | "act" | "site-complete" | "run-complete" | "error",
    hook: str?,
    category: "injection" | "intent" | "download" | "credential" | "cert",
    decision: "allow" | "block",
    severity: "info" | "low" | "medium" | "high" | "critical",
    reason: str,
    evidence: dict,
    latency_ms: int,
)
```

### HTTP Endpoints
- `GET  /` → dashboard (index.html)
- `GET  /events` → SSE stream of SecurityEvents
- `POST /run/synthetic` → scripted demo (no keys needed)
- `POST /run?enforce=on|off` → real traversal (TODO: wire to P1's loop)
- `GET  /scorecard` → { "hooks-off": {...}, "hooks-on": {...} }
- `POST /scorecard/run` → run both passes, cache result

## Testing Strategy

**Level 1 (unit):**
```bash
python test_hooks.py        # 3 deterministic hooks work standalone
```

**Level 2 (integration):**
```bash
python test_integration.py  # sinks, registry, synthetic all together
```

**Level 3 (e2e, manual):**
1. `curl -X POST http://localhost:8000/run/synthetic`
2. Open http://localhost:8000
3. Watch live feed, threat counter, BLOCKED hero
4. Click "Compute scorecard" → see before/after

## Performance Notes

- Deterministic hooks: <1ms each (pure functions)
- Hook registry: runs all in parallel, aggregates in ms
- SSE: per-connection queue, non-blocking (failures swallowed)
- MemorySink: in-memory list, linear scan for tally (fine for <10k events)
- Dashboard: vanilla JS, ~2KB gzipped, works offline (Tailwind via CDN)

## Modularity Checklist

✅ **Events:** SecurityEvent is the only cross-module type  
✅ **Hooks:** no dependencies on browser/llm/controlloop  
✅ **Sinks:** fire-and-forget, never block the pipeline  
✅ **Dashboard:** EventSource + vanilla JS, no build  
✅ **Server:** thin FastAPI wrapper, all logic in libraries  
✅ **Tests:** async-friendly, no fixtures, < 100 lines each  

## Roadmap (depends on P1)

1. ✓ **Phase 0:** Synthetic demo proves the wire (done)
2. ⏳ **Phase 1:** P1 wires Stagehand + BrowserSession + hero hooks
3. ⏳ **Phase 2:** P1 implements control loop (observe → hooks → act → publish)
4. ⏳ **Phase 3:** Scorecard runner runs both passes
5. ⏳ **Phase 4:** Red-team URL drops in → live demo on stage

## Environment Variables

```bash
ENV=LOCAL                           # LOCAL (dev, no browser) | BROWSERBASE (production)
BROWSERBASE_API_KEY=                # Only needed if ENV=BROWSERBASE
BROWSERBASE_PROJECT_ID=             # Only needed if ENV=BROWSERBASE
ANTHROPIC_API_KEY=                  # Only needed for hero hooks (P1)
ANTHROPIC_MODEL=claude-3-5-sonnet   # LLM for injection + intent-drift detection
SENTRY_DSN=                         # Optional: enable error reporting
PORT=8000                           # Dashboard port
```

## Cost Control (You have $25 API credit)

🔴 **DO NOT** set ANTHROPIC_API_KEY unless testing P1's hero hooks.  
The synthetic demo works without it — zero LLM cost.

✅ **DO** use the synthetic demo for all Person 2 work.  
✅ **DO** test deterministic hooks (no LLM, instant).  
✅ **DO** wait for P1 before enabling real traversal.

When real traversal starts (P1 ready):
- Each step costs ~$0.01 (prompt injection + intent drift)
- 5 sites × ~10 steps = ~$0.50 per demo
- Your $25 = ~50 full demos

## Troubleshooting

**"ModuleNotFoundError: No module named 'browsecheck'"**  
Make sure you're running from the repo root (`cd /Users/dojha/Desktop/BrowseCheck`).

**"Port 8000 already in use"**  
```bash
lsof -i :8000
kill -9 <PID>
```

**"SSE connection closes immediately"**  
Check server logs: `tail -20 /tmp/server.log` or restart with `--reload`.

**"Scorecard shows 0 blocks"**  
The synthetic demo is async (fire-and-forget). Wait 8-10 seconds after POST, then check.

**"Hooks not blocking"**  
Are they enabled in `hooks/factory.py`? Check `deterministic=True` in the registry.
