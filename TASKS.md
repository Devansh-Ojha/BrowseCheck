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

**Scope of THIS repo:** the agent (Claude tool-use loop over CDP/Browserbase),
the hook pipeline, the control loop, observability, the live dashboard, and the
scorecard. We do NOT build the malicious sites (the red team does — we get URLs).

## 2. Architecture at a glance

```
         user task + 5 sites
                 │
   ┌─────────────▼───────────────┐
   │  control loop (P1)           │   each turn Claude proposes a
   │  tool_use ─► hooks ─► act()  │     tool call (navigate/click/
   └─────────────┬───────────────┘     fill/read_page/finish)
                 │ publishes            if BLOCK: never execute it
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
Architecture (decided): we own the loop via the **Anthropic tool-use API** and
execute browser tools over **CDP with Playwright** (Browserbase or local). Every
`tool_use` is gated by the hook pipeline before it touches the browser — so
pre-action gating is guaranteed by construction (this retired risk #1). No Stagehand.

Files you own:
- `browser/session.py` — Playwright/CDP executor: `start()` (connect_over_cdp to Browserbase / local Chromium), `BROWSER_TOOLS` schema, `execute_tool()`, `snapshot()`.
- `browser/replay.py` — Browserbase live-view URL for the dashboard iframe.
- `controlloop/loop.py` — the Claude tool-use loop: gate every `tool_use` (incl. `finish` = relay surface) before executing; block short-circuit.
- `llm/provider.py` — Anthropic wrapper: `classify()` (hooks) + `respond()` (agent loop).
- `hooks/prompt_injection.py` — **HERO 1, build first.**
- `hooks/intent_drift.py` — **HERO 2.**
- `tasks/demo_task.py` — fill in the 4 real benign URLs.
- `server/app.py` `/run` endpoint — wire the real traversal (TODO marked inline).

Ordered:
1. Install + browser: `pip install -r requirements.txt && python -m playwright install chromium`.
2. Get `BrowserSession` working LOCAL: `start` -> `goto` -> `read_page`/`click`/`fill` -> `snapshot`.
3. Implement `PromptInjectionHook` against saved adversarial HTML snippets (unit test it).
4. Run `controlloop/loop.py` LOCAL with prompt-injection only; confirm a `tool_use` is gated BEFORE `execute_tool`, and events hit the bus.
5. Implement `IntentDriftHook`; add to registry. Then the red-team tasks A–E (section 6).
6. Flip `ENV=BROWSERBASE`: verify `_create_browserbase_session()` connectUrl + CDP connect; wire live-view URL.
7. Add `snapshot()` pending_download + cert capture (feeds P2's deterministic hooks).
8. When the red-team URL lands: add to `demo_task.py`, run, confirm the live block — `read_page` on the poisoned page returns BLOCKED (poison never enters context) and any `finish` relay is blocked.

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
1. P1 loop gates a `tool_use` locally ➜ 2. P1 prompt-injection blocks on a snippet ➜
3. P2 dashboard shows that block via the real bus ➜ **MILESTONE: pipeline proven**
➜ 4. breadth (intent-drift, deterministic, scorecard, live-view) ➜
5. red-team URL drops in ➜ **live hero block.**

## Integration contract between P1 and P2
- P1 publishes `SecurityEvent`s via `event_bus.publish(...)` (already wired in the loop).
- P2 consumes them via SSE — never imports P1's modules. Synthetic emitter proves the wire.

---

## 6. Red-team attack methodology & our defense mapping

The red team's attack is an **indirect prompt injection that targets the agent's
OUTPUT, not a browser action.** The hidden payload doesn't make the agent enter
credentials itself — it makes the agent *tell the user* to go sign in at a
look-alike phishing page ("your session expired, sign in here [link]"). The
human then types credentials into the fake page.

**Architectural consequence (READ THIS):** pure action-gating can miss this,
because the harmful step may be a *text answer to the user*, not a click. So we
must (a) scan every page the moment we land on it — before the agent reasons —
and (b) treat the agent's user-facing answer as a gated step, not just clicks.
Detect-at-source + block-before-relay is our story, and it's a differentiator:
action-only guards don't catch the relay vector.

### Technique → defense
| Red-team technique | Hides in | Defense | Owner |
|---|---|---|---|
| Fake `[SYSTEM MESSAGE]`/`[SYSTEM ALERT]`, "ignore all previous instructions", session-expired / premium / account-alert angles | page or hidden text | `prompt_injection` LLM scan | P1 |
| Invisible CSS: `display:none`, `visibility:hidden`, `font-size:0`, `color:transparent`, `opacity:0`, off-screen | hidden DOM | hidden-vs-rendered diff: any directive present in DOM but not visible = strong block signal | P1 |
| Image `alt`-text directive | `<img alt="...">` | extract & scan all `alt` attributes | P1 |
| HTML comment directive | `<!-- ... -->` | extract & scan comments | P1 |
| Base64 / obfuscated "decode and follow" payload | encoded string | deterministically decode suspicious tokens, scan decoded text, flag the "decode & follow" meta-instruction | P1 |
| Social-engineering **relay** (agent told to direct USER to sign in at link) | agent output | page-entry scan blocks before relay; `intent_drift` flags "direct user to authenticate / external login" as out-of-scope | P1 |
| Look-alike domain (`accounts-google.com`) | phishing link / form action | `credential_phish`: typosquat/homoglyph/extra-word/different-TLD check vs legit auth domains | P2 |
| Mirrored login page / static form mimicking OAuth | capture page | `credential_phish`: password field on non-auth domain + form-action mismatch + no real OAuth redirect | P2 |

### P1 — NEW tasks (fold into section "Person 1" ordered list)
- **A. Page-entry scan (control loop):** run the hook pipeline immediately after
  `goto`, before/independent of `observe()`, so a poisoned page is caught even
  when the agent proposes no click. Also gate the agent's final answer/relay.
- **B. Injection-surface extraction (`snapshot`):** extract hidden-element text,
  all `alt` attributes, and HTML comments; compute the hidden-vs-rendered diff;
  decode base64/obfuscated tokens. Feed these explicitly to `prompt_injection`
  (improves recall + cuts tokens + beats the base64 evasion pro-tip).
- **C. Harden `prompt_injection` prompt:** name these exact payload shapes + the
  relay pattern + the base64 "decode & follow" trick; require flagging any
  directive that appears only in hidden/alt/comment surfaces.
- **D. `intent_drift` relay rule:** explicitly block proposing to tell the user
  to authenticate / visit an external login during a form-fill task.
- **E. Regression snippets:** save HTML fixtures for all 3 angles (A/B/C) × all 3
  embeddings (invisible CSS, alt-text, base64) and unit-test => block.

### P2 — coordination
- `credential_phish`: add look-alike detection (hyphen/extra-word/TLD swap/
  homoglyph) vs `LEGIT_AUTH_DOMAINS`; block password fields on near-match hosts.
- Dashboard hero copy for the relay case, e.g. *"BLOCKED — page tried to make the
  agent send you to a fake login (accounts-google.com)."*

### Open questions for the red team / you (before the URL lands)
1. Is the hidden injection embedded in one of the 5 task sites (the fake Berkeley
   portal), and is the credential-capture page the SAME page or a separate link
   the agent is told to relay? (Decides whether the demo block is page-entry
   injection detection, credential-form detection, or both.)
2. Which angle (A/B/C) and which embedding (invisible CSS / alt-text / base64)
   will the demo URL use, so our fixtures + demo match exactly?
3. Do we want the hero block to demonstrate the **relay** ("agent was about to
   tell you to sign in at …") — the novel, differentiating angle — vs. an action?
4. What exact look-alike domain will the capture page use, so `credential_phish`
   can be tuned/tested against it?
