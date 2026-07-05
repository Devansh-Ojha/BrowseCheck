# BrowseCheck: Runtime Security for Browser Agents

## Inspiration

Browser agents are about to be everywhere. They read pages, click buttons, fill forms, log in, download files, and move money. Every page they visit is attacker-controlled. Today, the only protection is whether the model is "smart enough" to ignore malicious instructions. **That is not a security guarantee. It is hope.**

Infrastructure providers like Browserbase offer excellent remote browsers, but they solve infrastructure, not trust. They don't make application-level decisions about whether an action is safe for a user's task. That leaves a critical security gap.

Our key insight came while building: Claude correctly rejected an obvious prompt injection. But **security should not depend on model capability.** A subtle attack or weaker model changes everything. We built an **external, deterministic security layer** so any browser agent—even a jailbroken one—inherits the same guarantees.

## What it does

BrowseCheck sits between agent and browser. Every proposed action passes through a security pipeline before execution. If an action is malicious or outside the user's intent, it is blocked before the browser performs it.

All hooks run in parallel, fail-closed: **any hook blocks → action denied.**

### Current hooks:

- **Prompt Injection (LLM)** — Detects adversarial instructions in visible/hidden page content
- **Intent Drift (LLM)** — Ensures the agent stays within the user's task (blocks login attempts during read-only tasks, for example)
- **Credential Phishing (Deterministic)** — Detects password forms on untrusted domains and fake OAuth pages using allowlists
- **Download Inspection (Deterministic)** — Blocks executables and suspicious files
- **Certificate & SSL (Deterministic)** — Rejects insecure connections

### The demonstration

A realistic fake "UC Berkeley AI Hackathon 2026" site with a convincing Google OAuth page and malicious extension download. Same agent, two runs:
- **Unprotected** → falls for phishing
- **With BrowseCheck** → blocked at every step

Control test on legitimate sites shows zero false positives.

## How we built it

BrowseCheck owns the agent control loop using Claude's tool-use API. Browser actions (navigate, read, click, fill, finish) execute through Playwright over Chrome DevTools Protocol on Browserbase or local Chromium.

**Before every action executes, it is intercepted by the security pipeline.**

Hooks run asynchronously in parallel. Failures or timeouts cannot silently allow unsafe actions—fail-closed by design. LLM hooks handle nuanced reasoning (injection, drift). Deterministic hooks provide guarantees that never depend on model behavior.

Security events flow through an event bus to an in-memory scorecard, Server-Sent Events for the live dashboard, and optional Sentry integration. Backend: FastAPI + SSE streaming. Frontend: vanilla JS + Tailwind, embedding Browserbase's live browser view alongside security events and a hard stop that terminates both agent and browser.

## Challenges we ran into

**Obvious vs. realistic attacks**: Our original attacks were too obvious. Claude correctly detected them, but that made for an unconvincing demo. The real insight: realistic social engineering is far more dangerous than jailbreaks. Security cannot rely on the model making the right decision every time.

**Action interception timing**: Intercepting browser actions before side effects occurred while preserving natural agent workflow was non-trivial.

**Fail-closed design**: If an LLM hook timed out or failed, the system needed to surface the error while ensuring unsafe actions were never executed.

**OAuth vs. phishing**: Distinguishing legitimate OAuth flows from convincing phishing pages required deterministic analysis, not model judgment.

**False positives and integration**: Minimizing false positives while integrating Browserbase sessions with live SSE streaming and reliable cleanup.

## Accomplishments that we're proud of

- **Security independent of model behavior.** The same agent that falls for phishing without BrowseCheck is fully protected when enabled.
- **Realistic phishing demo.** Real cloud browser, real attack, live prevention.
- **Modular hooks.** Deterministic + LLM checks. Easy to add new protections.
- **Credentials never exposed.** Unsafe auth pages are blocked before entry.
- **No false positives.** Legitimate workflows remain fully usable.

## What we learned

1. **"The model will know better" is not a security strategy.** Model behavior changes across architectures and prompts. External enforcement is the only reliable guarantee.

2. **The most dangerous attacks are realistic social engineering, not jailbreaks.** Browser agents are designed to be helpful—which makes them especially vulnerable to convincing phishing.

3. **Defense in depth works.** Intent validation + injection detection + phishing prevention + download inspection combine to be stronger than any single technique.

4. **Browser infrastructure and browser security are separate problems.** Infrastructure provides reliable execution. Security requires understanding user intent and action risk.

## What's next for BrowseCheck

- **Drop-in SDK/proxy** for any browser agent (Browserbase, Playwright, computer-use) with minimal integration
- **Expanded deterministic hooks** — PII exfiltration, payment authorization, OAuth verification, file uploads, org-specific allowlists
- **Policy engine** — task-specific security policies, optional human approval for high-impact actions
- **Signed audit logs** — every allow/block decision for compliance and forensics
- **Performance optimization** — caching and lightweight local classifiers to reduce LLM latency
- **Public red-team benchmark** — prompt injection and phishing scenarios for CI/CD evaluation of browser agent security
