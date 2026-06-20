"""Event sinks. OWNER: Person 2.

A sink is anything that consumes SecurityEvents. Three ship now:
  - MemorySink : keeps events for the scorecard tally
  - SSESink    : fans events out to dashboard browser connections
  - SentrySink : DISABLED unless SENTRY_DSN is set (naive-now / Sentry-later)

Because SecurityEvent already carries everything, SentrySink is a pure mapping
and needs no changes anywhere else when you turn it on.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections import Counter

from ..config import Settings
from ..contracts import RunMode, SecurityEvent


class EventSink(ABC):
    @abstractmethod
    async def handle(self, event: SecurityEvent) -> None: ...


class MemorySink(EventSink):
    """Stores events so the scorecard can tally threats per run mode."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def handle(self, event: SecurityEvent) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()

    def tally(self) -> dict:
        """Scorecard data: blocks by category for each run mode.
        hooks-off blocks == 'threats that got through';
        hooks-on blocks  == 'threats blocked'."""
        out: dict[RunMode, dict] = {
            "hooks-off": {"total": 0, "by_category": Counter()},
            "hooks-on": {"total": 0, "by_category": Counter()},
        }
        for e in self.events:
            if e.kind == "hook-block" and e.run_mode in out:
                out[e.run_mode]["total"] += 1
                out[e.run_mode]["by_category"][e.category or "unknown"] += 1
        # make JSON-friendly
        return {
            mode: {"total": d["total"], "by_category": dict(d["by_category"])}
            for mode, d in out.items()
        }


class SSESink(EventSink):
    """Fans events out to all connected dashboard browsers via per-connection
    asyncio queues. The FastAPI /events endpoint subscribes/unsubscribes."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[SecurityEvent]] = set()

    def subscribe(self) -> "asyncio.Queue[SecurityEvent]":
        q: asyncio.Queue[SecurityEvent] = asyncio.Queue()
        self._queues.add(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue[SecurityEvent]") -> None:
        self._queues.discard(q)

    async def handle(self, event: SecurityEvent) -> None:
        for q in list(self._queues):
            q.put_nowait(event)


class SentrySink(EventSink):
    """OFF unless SENTRY_DSN is set. Data spec to implement when enabling:

      - init once with the DSN (traces_sample_rate=1.0 for the demo)
      - tag every event with: hook, category, decision, severity, domain, run_mode
      - on 'hook-block': sentry_sdk.capture_message(f"BLOCK {hook} @ {domain}",
            level="warning") + set_context("evidence", event.evidence)
      - on 'hook-pass': add_breadcrumb so a later block carries its trail
      - (optional) one span per hook eval with latency_ms as a measurement,
        so Sentry shows per-hook latency + decision dashboards = "status of every hook"
    """

    def __init__(self, settings: Settings) -> None:
        self.enabled = settings.sentry_enabled
        self._sentry = None
        if self.enabled:
            import sentry_sdk

            sentry_sdk.init(dsn=settings.sentry_dsn, traces_sample_rate=1.0)
            self._sentry = sentry_sdk

    async def handle(self, event: SecurityEvent) -> None:
        if not self.enabled or self._sentry is None:
            return
        s = self._sentry
        with s.push_scope() as scope:
            scope.set_tag("hook", event.hook or "")
            scope.set_tag("category", event.category or "")
            scope.set_tag("decision", event.decision.value if event.decision else "")
            scope.set_tag("severity", event.severity.value if event.severity else "")
            scope.set_tag("domain", event.site.domain or "")
            scope.set_tag("run_mode", event.run_mode)
            if event.kind == "hook-block":
                scope.set_context("evidence", event.evidence or {})
                s.capture_message(
                    f"BLOCK {event.hook} @ {event.site.domain}", level="warning"
                )
            else:
                s.add_breadcrumb(
                    category="hook",
                    message=f"{event.kind} {event.hook} @ {event.site.domain}",
                    level="info",
                )
