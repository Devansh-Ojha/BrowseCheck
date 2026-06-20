# BrowseCheck — Onboarding & Task Split (2 engineers, ~18h)

> **Teammate (Person 2): start at section 1, then run section 3, then do section 5.**
> You can build and demo your entire half today with **no API keys** — see section 3.

---

## 1. What we're building (context)

**BrowseCheck is a runtime security layer for AI browser agents.** Agentic
browsers are exploding in 2026, and a single malicious web page can hijack an
agent via hidden prompt injections, fake login forms, or malicious downloads —
making it leak data or take actions the user never asked for. Browserbase (the
cloud browser our agent runs on) gives agents the web; **we make it safe.**

The key idea is **prevention, not observation (non-negotiable):** for every step
the agent wants to take, we inspect the proposed action + page *before* it runs,
and only allow it if a pipeline of security hooks passes. We own the control
loop (`observe → hooks → act`); we never hand control to an uninterruptible
autonomous agent.

**The demo:** a user gives the agent an innocent task (*"fill out these hackathon
application forms"*). The agent visits 5 sites on Browserbase. Four are benign —
it sails through, hooks glow green. The fifth is a **fake Berkeley hackathon
portal** (built by a separate red-team repo, delivered as a URL) that hides a
prompt injection + a credential-harvesting form. **Our layer blocks it live,
before the agent acts** — the threat pops on the dashboard. Then a before/after
scorecard shows "threats through (protection off) vs blocked (protection on)".

**Scope of THIS repo:** the agent, Stagehand/Browserbase integration, the hook
pipeline, the control loop, observability, the live dashboard, and the scorecard.
We do NOT build the malicious sites (the red team does — we just get URLs).

## 2. Architecture at a glance

```
         user task + 5 sites
                 │
   ┌─────────────▼───────────────┐
   │  control loop (P1)           │   for each step:
   │  observe() ─► hooks ─► act() │     observe proposed action
   └─────────────┬───────────────┘     run hook pipeline
                 │ publishes            if BLOCK: stop, never act()
                 ▼
         SecurityEvent  ──►  event_bus  ──►  sinks (P2)
                                              ├─ MemorySink  → scorecard tally
                                              ├─ SSESink     → dashboard (live feed)
                                              └─ SentrySink  → Sentry (off until DSN set)
```

Hooks (each returns allow/block + reason + severity + evidence):
- **prompt_injection** (HERO, P1, LLM) — hidden/adversarial instructions.
- **intent_drift** (HERO, P1, LLM) — actions outside the user's task scope.
- **download_inspect / credential_phish / cert_ssl** (deterministic, P2).

## 3. Setup & run (do this FIRST — works today, no keys needed)

```bash
pip install -r requirements.txt
cp .env.example .env          # P2: you can leave all keys BLANK for synthetic work
uvicorn browsecheck.server.app:app --reload --port 8000
```
Open http://localhost:8000 and click **"Run demo (synthetic)"**. You should see:
- the live hook feed stream green PASS rows for 4 benign sites,
- the site timeline turn green,
- on the 5th site, two red **BLOCK** rows and the big **BLOCKED** hero overlay,
- the threat tally increment, and the scorecard columns populate.

The synthetic run (`browsecheck/demo/synthetic.py`) emits scripted `SecurityEvent`s
through the **real** bus + SSE — so your dashboard/scorecard are fully exercised
without a browser, an LLM, or the red-team URL. **You only need Browserbase /
Anthropic keys once you integrate with P1's live loop (section 5, step 5+).**

## 4. The frozen contract (build against this, don't change it)

Everything flows as one `SecurityEvent` (see `browsecheck/contracts.py`). Fields
your UI/sinks care about:
- `kind`: `navigate | observe | hook-pass | hook-block | act | site-complete | run-complete`
- `site`: `{ url, domain, label }`
- `hook`, `category` (`injection|intent|download|credential|cert`), `decision`
  (`allow|block`), `severity` (`info|low|medium|high|critical`), `reason`,
  `evidence`, `latency_ms`, `run_mode` (`hooks-on|hooks-off`).

P1 publishes these; you consume them via SSE and never import P1's modules.
Change the contract only by mutual consent.

---

## Person 1 (repo owner) — control loop + Browserbase + 2 hero hooks
Files you own:
- `browser/session.py` — Stagehand init (LOCAL/BROWSERBASE), `observe()`, `act()`, `snapshot()`.
- `browser/replay.py` — Browserbase live-view URL for the dashboard iframe.
- `controlloop/loop.py` — observe -> hooks -> act -> log; the block short-circuit.
- `llm/provider.py` — Anthropic wrapper (already stubbed; tune prompts/timeouts).
- `hooks/prompt_injection.py` — **HERO 1, build first.**
- `hooks/intent_drift.py` — **HERO 2.**
- `tasks/demo_task.py` — fill in the 4 real benign URLs.
- `server/app.py` `/run` endpoint — wire the real traversal (TODO marked inline).

Ordered:
1. **RISK SPIKE (hour 0–2):** confirm Stagehand Python `observe()` returns an
   inspectable proposal and `act()` runs ONLY that — true pre-action gating. If
   not, fall back (pin version / Playwright+LLM / TS). *Blocks everything.*
2. Get `BrowserSession` working LOCAL: goto -> observe -> snapshot -> act on a benign page.
3. Implement `PromptInjectionHook` against saved adversarial HTML snippets (unit test it).
4. Wire `controlloop/loop.py` with prompt-injection only; emit events to the bus.
5. Implement `IntentDriftHook`; add to registry.
6. Flip `ENV=BROWSERBASE`; verify parity; wire live-view URL.
7. Add `snapshot()` pending_download + cert capture (feeds P2's deterministic hooks).
8. When the red-team URL lands: add to `demo_task.py`, run, confirm live block before `act()`.

## 5. Person 2 (TEAMMATE) — events + Sentry + dashboard + scorecard + deterministic hooks

**You need: just Python.** No Browserbase or Anthropic key until step 5. The
deterministic hooks need no LLM. Test hooks against saved HTML strings.

Files you own:
- `events/bus.py`, `events/sinks.py` — bus + Memory/SSE/Sentry sinks (scaffolded).
- `server/app.py` — SSE endpoint, static serving, scorecard endpoints (scaffolded).
- `demo/synthetic.py` — scripted run for building the UI (scaffolded).
- `dashboard/index.html` — minimalist live dashboard (scaffolded).
- `scorecard/runner.py` — hooks-off vs hooks-on tally (scaffolded).
- `hooks/download_inspect.py`, `hooks/credential_phish.py`, `hooks/cert_ssl.py` — deterministic.

Ordered:
1. **Boot the server + dashboard, run `/run/synthetic`** — confirm SSE events
   stream into the live feed and the BLOCKED hero fires. (Works today.)
2. Polish dashboard: site timeline states, threat tally, BLOCKED hero, layout.
3. Verify `MemorySink.tally()` + `/scorecard` render the before/after columns.
4. Build the 3 deterministic hooks against saved HTML snippets (baselines exist):
   harden `credential_phish` for the fake Berkeley portal pattern.
5. Embed Browserbase live-view iframe (P1 supplies the URL).
6. **Sentry (when ready):** flip on by setting `SENTRY_DSN`. Implement the
   mapping per the spec in `events/sinks.py:SentrySink` — tag every event with
   `hook/category/decision/severity/domain/run_mode`; `capture_message` on block;
   breadcrumbs on pass. Goal: per-hook status visible in Sentry.
7. `scorecard/runner.py`: once P1's loop is live, run both passes; cache result;
   keep a recorded fallback for stage.

---

## Critical path (one end-to-end block first, then breadth)
1. P1 risk spike passes ➜ 2. P1 prompt-injection blocks on a snippet ➜
3. P2 dashboard shows that block via the real bus ➜ **MILESTONE: pipeline proven**
➜ 4. breadth (intent-drift, deterministic, scorecard, live-view) ➜
5. red-team URL drops in ➜ **live hero block.**

## Integration contract between P1 and P2
- P1 publishes `SecurityEvent`s via `event_bus.publish(...)` (already wired in the loop).
- P2 consumes them via SSE — never imports P1's modules. Synthetic emitter proves the wire.
