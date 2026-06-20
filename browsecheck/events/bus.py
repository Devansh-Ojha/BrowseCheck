"""In-process async event bus + shared sink singletons. OWNER: Person 2.

The control loop publishes; sinks consume. Observability must NEVER break the
loop, so a failing sink is swallowed.
"""

from __future__ import annotations

from ..config import get_settings
from ..contracts import SecurityEvent
from .sinks import EventSink, MemorySink, SentrySink, SSESink


class EventBus:
    def __init__(self) -> None:
        self._sinks: list[EventSink] = []

    def add_sink(self, sink: EventSink) -> EventSink:
        self._sinks.append(sink)
        return sink

    async def publish(self, event: SecurityEvent) -> None:
        for sink in self._sinks:
            try:
                await sink.handle(event)
            except Exception:  # noqa: BLE001  — never let a sink break the agent
                pass


# Shared singletons (import these everywhere).
event_bus = EventBus()
memory_sink: MemorySink = event_bus.add_sink(MemorySink())          # type: ignore[assignment]
sse_sink: SSESink = event_bus.add_sink(SSESink())                   # type: ignore[assignment]
sentry_sink: SentrySink = event_bus.add_sink(SentrySink(get_settings()))  # type: ignore[assignment]
