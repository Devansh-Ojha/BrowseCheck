"""Scorecard runner. OWNER: Person 2.

Runs the SAME traversal twice over the SAME sites — once with enforcement off
(threats get through) and once on (threats blocked) — then reads the tally from
the MemorySink. The only difference between runs is the `enforce` flag in the
control loop; identical hook evaluations otherwise.

Build against the synthetic emitter first; swap in the real control loop once
P1's BrowserSession is live. De-risk for stage: run once, cache, render live.
"""

from __future__ import annotations

from ..contracts import SiteRef, new_id
from ..events.bus import event_bus, memory_sink
from ..hooks.factory import build_registry


async def run_scorecard(user_task: str, sites: list[SiteRef]) -> dict:
    """Returns {'hooks-off': {...}, 'hooks-on': {...}} block tallies by category."""
    # Lazy import so the server can boot without the browser SDK installed.
    from ..browser.session import BrowserSession
    from ..controlloop.loop import run_traversal

    memory_sink.clear()

    for enforce, run_mode in ((False, "hooks-off"), (True, "hooks-on")):
        session = BrowserSession(expose_hidden_surfaces=not enforce)
        await session.start()
        try:
            registry = build_registry()
            await run_traversal(
                session, registry,
                user_task=user_task, sites=sites,
                enforce=enforce, run_mode=run_mode,  # type: ignore[arg-type]
                session_id=new_id(),
                agent_profile="protected" if enforce else "naive",
            )
        finally:
            await session.close()

    return memory_sink.tally()


# Used by the bus singleton import to ensure event_bus is initialised.
_ = event_bus
