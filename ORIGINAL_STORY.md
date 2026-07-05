# BrowseCheck: Runtime Security for Browser Agents

## Inspiration

Browser agents are about to be everywhere. They read pages, click buttons, fill forms, log in, download files, and even move money. Every page they interact with is attacker-controlled, yet today the only thing protecting users is whether the model is "smart enough" to ignore malicious instructions. That is not a security guarantee. **It is hope.**

Infrastructure providers like Browserbase offer excellent remote browsers, but they are intentionally infrastructure. They do not make application-level trust decisions about whether a particular action is safe for a user's task. That leaves a critical security gap.

While building BrowseCheck, we watched Claude correctly reject an obvious prompt injection. That became our key insight. **Security should not depend on how capable the underlying model happens to be.** A more subtle attack or a weaker model can completely change the outcome. Instead of relying on model behavior, we built an external, deterministic security layer so any browser agent, even a weaker or jailbroken one, inherits the same security guarantees.

## What it does

BrowseCheck is a runtime security layer that sits between any browser agent and the browser. Every action proposed by the agent passes through a security pipeline before it executes. If an action is malicious or outside the user's intended task, it is blocked before the browser can perform it.

All security hooks run in parallel and follow a fail-closed policy. If any hook blocks an action, the action is denied.

### Current hooks include:

- **Prompt Injection (LLM)**: Detects hidden or adversarial instructions embedded in visible or hidden page content.
- **Intent Drift (LLM)**: Ensures the agent stays within the user's original task. For example, it blocks login attempts during a read-only summarization task, even if the website urges the user to sign in.
- **Credential Phishing (Deterministic)**: Detects password forms on untrusted domains and fake OAuth pages using authentication allowlists and form analysis. High-severity pages are flagged, and credentials are never entered.
- **Download Inspection (Deterministic)**: Blocks suspicious downloads such as executables or malicious browser extensions.
- **Cross-Site Carryover**: Prevents malicious instructions gathered on one website from influencing behavior on another.
- **Certificate & SSL Validation (Deterministic)**: Blocks insecure or invalid HTTPS connections.

### The demonstration

Our live dashboard demonstrates the same poisoned website with two identical agents running side by side. One runs without protection while the other uses BrowseCheck. Both use the same model. The dashboard embeds the live Browserbase session, streams security events in real time, and displays a before-and-after security scorecard. A control experiment on the legitimate website demonstrates that BrowseCheck does not generate unnecessary false positives.

For our demo, we built a realistic fake "UC Berkeley AI Hackathon 2026" website. The site attempts to lure the agent into signing into a fake Google login page and installing a malicious browser extension. The unprotected agent follows the attack, while BrowseCheck blocks every malicious action.

## How we built it

BrowseCheck owns the browser agent control loop using Anthropic Claude's tool-use API. Browser actions such as navigation, reading pages, clicking, filling forms, and finishing tasks are executed through Playwright over the Chrome DevTools Protocol using Browserbase cloud sessions or local Chromium.

**Before every browser action executes, it is intercepted and evaluated by the security pipeline.**

The hook system executes asynchronously in parallel and aggregates every result into a single allow-or-block decision. The pipeline is fail-closed, combines evidence from all hooks, and assigns the highest detected severity. Individual hook failures or timeouts cannot silently allow unsafe actions.

We separate hooks into two categories:

- **LLM-based reasoning hooks** for nuanced decisions such as prompt injection and intent drift.
- **Deterministic hooks** for security guarantees that should never depend on model reasoning.

Security events are published through an event bus to multiple sinks, including an in-memory scorecard, Server-Sent Events for the live dashboard, and an optional Sentry integration.

The backend is built with FastAPI and streams updates over Server-Sent Events. The frontend uses vanilla JavaScript and Tailwind CSS, embedding Browserbase's live browser view alongside security events, run controls, and a hard stop that immediately terminates both the browser session and the agent.

To test BrowseCheck, we built a realistic phishing environment using Astro and Tailwind CSS. The site includes a fake Google OAuth flow, a convincing "sign in for confirmed details" prompt, and a malicious browser extension download. It is deployed on Netlify so the cloud browser interacts with it like any real website.

## Challenges we ran into

**Attack obviousness**: Our original attacks were too obvious. Claude correctly detected and rejected them, which was good for security but made for an unconvincing demo. That led to our biggest insight: realistic social engineering is significantly more dangerous than obvious prompt injection. Security cannot rely on the model making the right decision every time.

**Action interception**: Another challenge was intercepting browser actions before side effects occurred while preserving a natural agent workflow.

**Fail-closed design**: Designing a fail-closed pipeline required careful engineering. If an LLM hook timed out or failed, the system needed to surface the error while ensuring unsafe actions were never executed.

**OAuth vs phishing distinction**: Distinguishing legitimate OAuth flows from convincing phishing pages required deterministic analysis rather than model judgment.

**False positives and integration**: Finally, we worked to minimize false positives so legitimate websites remain fully usable, and integrated Browserbase sessions with live Server-Sent Event streaming and reliable cleanup.

## Accomplishments that we're proud of

- **Security that does not depend on model behavior.** The same agent that falls for phishing without BrowseCheck is fully protected when BrowseCheck is enabled.
- **A complete end-to-end demonstration** featuring a real cloud browser, a realistic phishing website, and live attack prevention.
- **A modular hook architecture** combining deterministic and LLM-based security checks, making new protections easy to add.
- **Credentials are never entered into suspicious websites.** Unsafe authentication pages are detected and blocked before any secrets are exposed.
- **A control experiment** demonstrating that BrowseCheck protects users without blocking legitimate workflows.

## What we learned

1. **"The model will know better" is not a security strategy.** Model behavior changes across architectures, prompts, and increasingly sophisticated attacks. The only reliable guarantees come from external security enforcement.

2. **The most dangerous attacks are often not jailbreaks but realistic social engineering.** Browser agents are designed to be helpful, which makes them especially vulnerable to convincing phishing attempts.

3. **Defense in depth is essential.** Intent validation, prompt injection detection, phishing prevention, and download inspection complement one another to provide stronger protection than any individual technique.

4. **Browser infrastructure and browser security solve different problems.** Infrastructure providers supply reliable browser execution, while security requires understanding both the user's intent and the risks of each action.

## What's next for BrowseCheck

- **Build a drop-in SDK and proxy** so any browser agent, whether Browserbase, Playwright, or computer-use frameworks, can inherit BrowseCheck's protections with minimal integration.
- **Expand deterministic hooks** to cover PII exfiltration, payment authorization, OAuth permission verification, file uploads, and organization-specific allowlists.
- **Develop a policy engine** supporting task-specific security policies and optional human approval for high-impact actions.
- **Create signed audit logs** for every allow and block decision to support compliance and forensic analysis.
- **Reduce latency** through caching and lightweight local classifiers that minimize reliance on LLM-based hooks.
- **Release a public red-team benchmark suite** containing prompt injection and phishing scenarios that developers can use to evaluate browser agent security in continuous integration.
