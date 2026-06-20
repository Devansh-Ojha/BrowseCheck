# Person 2 — Events + Dashboard + Hooks

## Current Status ✅

**Everything you own is working:**
- Server boots at `:8000`, serves dashboard
- SSE `/events` endpoint streams SecurityEvents to browser
- Synthetic demo runs, emits 2 blocks (injection + credential)
- MemorySink tallies blocks correctly
- `/scorecard` renders before/after columns
- All 3 deterministic hooks implemented + tested:
  - `download_inspect` — blocks .exe, double-ext, MIME mismatches
  - `credential_phish` — flags password fields on non-auth domains (nails fake Berkeley portal)
  - `cert_ssl` — blocks HTTP, validates TLS
- Sentry sink ready (disabled until SENTRY_DSN set)

Run tests:
```bash
python test_hooks.py          # verify all 3 hooks work
curl -X POST http://localhost:8000/run/synthetic
curl http://localhost:8000/scorecard | jq .
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Control Loop (Person 1)                                     │
│ observe() → hooks.run() → event_bus.publish()               │
└────────────────────────┬────────────────────────────────────┘
                         │ SecurityEvent
                         ▼
         ┌───────────────────────────────┐
         │ EventBus (events/bus.py)      │
         │ in-process async pub/sub      │
         └───────┬───────────┬───────────┘
                 │           │
        ┌────────▼──┐   ┌────▼─────────┐
        │MemorySink │   │ SSESink      │
        │ (tally)   │   │ (live feed)  │
        └───────────┘   └────┬─────────┘
                             │
                    ┌────────▼────────┐
                    │ Dashboard       │
                    │ (EventSource)   │
                    └─────────────────┘
         ┌────────────────────────────┐
         │ SentrySink (optional)      │
         │ (off unless SENTRY_DSN set)│
         └────────────────────────────┘
```

## Files You Own

```
browsecheck/
├── events/
│   ├── bus.py              ✅ EventBus + sink singletons
│   └── sinks.py            ✅ MemorySink / SSESink / SentrySink
├── hooks/
│   ├── download_inspect.py ✅ Block .exe, MIME mismatches
│   ├── credential_phish.py ✅ Flag phishing forms
│   └── cert_ssl.py         ✅ Block HTTP, invalid certs
├── server/
│   └── app.py              ✅ FastAPI endpoints
├── demo/
│   └── synthetic.py        ✅ Scripted run (no browser/LLM)
├── scorecard/
│   └── runner.py           ⏳ Needs P1's control loop
└── dashboard/
    └── index.html          ✅ Minimalist live feed + scorecard
```

## Next Steps (Blockers on P1)

### 1. Live-view iframe (P1 supplies URL)
Once P1 wires Browserbase, add to dashboard:
```html
<iframe id="liveView" src="[browserbase-live-view-url]"></iframe>
```
Currently stubbed at `dashboard/index.html:34`.

### 2. Scorecard runner (needs P1's BrowserSession + control loop)
`scorecard/runner.py` is scaffolded. It will:
- Run traversal with `enforce=False` (hooks-off)
- Run traversal with `enforce=True` (hooks-on)
- Tally blocks in both modes
- Cache for `/scorecard` endpoint

Wiring is in `/run` endpoint (`server/app.py:62`). When P1 marks BrowserSession ready, wire:
```python
# in server/app.py:/run
from ..scorecard.runner import run_scorecard
result = await run_scorecard(USER_TASK, demo_sites)
```

### 3. Sentry (optional, enable anytime)
```bash
export SENTRY_DSN="https://..."
# SentrySink auto-enables, tags every event
```
Already implemented in `sinks.py:78–120`. Just set the DSN.

## Testing

**Unit tests (no network):**
```bash
python test_hooks.py
```

**Integration (server must be running):**
```bash
python -m pytest  # when test suite exists
```

**Manual (dashboard at localhost:8000):**
1. Click "Run demo (synthetic)" — watch live feed + scorecard populate
2. Threat counter increments on each block
3. BLOCKED hero flashes on injection/phishing

## Monitoring

Check event flow:
```bash
curl http://localhost:8000/events --max-time 3 | head -20
```

Check scorecard (waits for synthetic to complete):
```bash
sleep 8 && curl http://localhost:8000/scorecard | jq .
```

## Code Quality

- **Deterministic hooks:** all pure functions, no I/O, fast (<1ms each)
- **Sinks:** fire-and-forget, never block the loop (exception-safe)
- **Dashboard:** vanilla JS, no build, Tailwind CDN (works offline if cached)
- **Bus:** in-process, no network latency, fail-safe (sink errors swallowed)

## API Contract (frozen, shared with P1)

`SecurityEvent` (single event type):
```json
{
  "id": "uuid",
  "ts": 1234567890.5,
  "session_id": "...",
  "run_mode": "hooks-on|hooks-off",
  "kind": "navigate|observe|hook-pass|hook-block|act|site-complete|run-complete|error",
  "site": { "url": "...", "domain": "...", "label": "..." },
  "hook": "prompt_injection|intent_drift|download_inspect|credential_phish|cert_ssl",
  "category": "injection|intent|download|credential|cert",
  "decision": "allow|block",
  "severity": "info|low|medium|high|critical",
  "reason": "...",
  "evidence": { ... },
  "latency_ms": 123
}
```

Never import P1's modules (browser, llm, controlloop). Consume only via SecurityEvent + EventBus.
