"""THE control loop: observe -> hooks -> act -> log. OWNER: Person 1.

Non-negotiable: prevention, not observation. act() is reached ONLY when the
aggregate decision is allow (or when enforce=False, i.e. the scorecard's
hooks-off run, where we still evaluate + log but let the action through to prove
what gets past an unprotected agent).
"""

from __future__ import annotations

from ..contracts import (
    Decision,
    HookContext,
    RunMode,
    SecurityEvent,
    SiteRef,
)
from ..events.bus import event_bus
from ..hooks.registry import HookRegistry

MAX_STEPS_PER_SITE = 8


def _step_goal(user_task: str) -> str:
    # TODO(P1): refine. For the demo this nudges Stagehand toward the next
    # task-relevant action so observe() returns a concrete proposal.
    return f"Take the next single action to make progress on: {user_task}"


async def run_traversal(
    session,                       # BrowserSession
    registry: HookRegistry,
    *,
    user_task: str,
    sites: list[SiteRef],
    enforce: bool,
    run_mode: RunMode,
    session_id: str,
) -> None:
    async def emit(**kw) -> None:
        await event_bus.publish(SecurityEvent(session_id=session_id,
                                              run_mode=run_mode, **kw))

    for site in sites:
        if not site.domain:
            site = SiteRef(url=site.url, domain="", label=site.label)
        await session.goto(site.url)
        await emit(kind="navigate", site=site)

        for step in range(MAX_STEPS_PER_SITE):
            observed = await session.observe(_step_goal(user_task))
            if not observed:
                break  # nothing left to do on this site
            action = observed[0]
            await emit(kind="observe", step_index=step, site=site,
                       reason=action.description)

            snapshot = await session.snapshot(site)
            ctx = HookContext(
                user_task=user_task,
                proposed_action=action,
                page=snapshot,
                step_index=step,
                session_id=session_id,
            )
            agg = await registry.run(ctx)

            # emit every hook firing (pass AND block)
            for result in agg.results:
                await event_bus.publish(
                    SecurityEvent.from_hook_result(
                        result, session_id=session_id, run_mode=run_mode,
                        step_index=step, site=site,
                    )
                )

            if agg.decision == Decision.BLOCK:
                await emit(
                    kind="hook-block", step_index=step, site=site,
                    severity=agg.severity, decision=Decision.BLOCK,
                    reason="; ".join(agg.reasons),
                    evidence={"blocking_hooks": agg.blocking_hooks},
                )
                if enforce:
                    # <-- SHORT-CIRCUIT: act() is NEVER called. Move on.
                    break
                # enforce=False: fall through and let the unsafe action run,
                # so the scorecard can count what got through.

            await session.act(0)        # only the observed action, only if allowed
            await emit(kind="act", step_index=step, site=site,
                       reason=action.description)

        await emit(kind="site-complete", site=site)

    await emit(kind="run-complete", site=SiteRef(url="", domain=""))
