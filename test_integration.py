#!/usr/bin/env python
"""Integration tests: verify the entire Person 2 stack works together."""

import asyncio
from browsecheck.contracts import Decision, SecurityEvent, Severity, SiteRef
from browsecheck.events.bus import event_bus, memory_sink, sse_sink
from browsecheck.demo.synthetic import run_synthetic
from browsecheck.hooks.download_inspect import DownloadInspectHook
from browsecheck.hooks.credential_phish import CredentialPhishHook
from browsecheck.hooks.cert_ssl import CertSslHook


async def test_sink_isolation():
    """Verify sinks don't interfere with each other."""
    memory_sink.clear()

    # Subscribe to SSE
    queue = sse_sink.subscribe()

    # Publish an event
    event = SecurityEvent(
        session_id="test",
        kind="hook-pass",  # type: ignore[arg-type]
        site=SiteRef(url="https://test.com", domain="test.com"),
        hook="test",
        category="injection",  # type: ignore[arg-type]
        decision=Decision.ALLOW,
    )
    await event_bus.publish(event)

    # Memory sink should have it
    assert len(memory_sink.events) == 1, "MemorySink should have 1 event"

    # SSE should have it
    received = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert received.id == event.id, "SSE should receive same event"

    sse_sink.unsubscribe(queue)
    print("✓ Sinks properly isolated (no cross-contamination)")


async def test_synthetic_end_to_end():
    """Full synthetic demo: verify all components work together."""
    memory_sink.clear()

    # Run the scripted demo
    await run_synthetic(delay=0.1)  # faster for testing

    # Verify event count
    event_count = len(memory_sink.events)
    assert event_count > 0, f"MemorySink should have events, got {event_count}"
    print(f"✓ Synthetic demo published {event_count} events")

    # Verify block tally
    tally = memory_sink.tally()
    on_blocks = tally["hooks-on"]["total"]
    assert on_blocks == 2, f"Expected 2 blocks, got {on_blocks}"
    print(f"✓ Tally correct: {on_blocks} blocks (injection + credential)")

    # Verify categories
    cats = tally["hooks-on"]["by_category"]
    assert cats.get("injection") == 1, "Expected 1 injection block"
    assert cats.get("credential") == 1, "Expected 1 credential block"
    print(f"✓ Categories correct: {cats}")


async def test_hook_registry_integration():
    """Verify deterministic hooks work with registry."""
    from browsecheck.hooks.registry import HookRegistry
    from browsecheck.contracts import HookContext, ObservedAction, PageSnapshot

    registry = HookRegistry()
    registry.register(DownloadInspectHook())
    registry.register(CredentialPhishHook())
    registry.register(CertSslHook())

    # Create a context with malicious indicators
    ctx = HookContext(
        user_task="fill form",
        proposed_action=ObservedAction(description="click submit"),
        page=PageSnapshot(
            url="http://example.com",  # HTTP = bad
            domain="evil.example",
            raw_html='<input type="password" /><form action="https://attacker.com"></form>',
            pending_download={"filename": "virus.exe", "mime": "text/plain", "user_initiated": False},
        ),
        step_index=0,
        session_id="test",
    )

    # Run registry
    decision = await registry.run(ctx)

    # Should block due to HTTP, phishing, and executable
    assert decision.decision == Decision.BLOCK, "Should block (HTTP + phishing + exe)"
    assert len(decision.blocking_hooks) == 3, f"Expected 3 blocking hooks, got {len(decision.blocking_hooks)}"
    assert decision.severity == Severity.CRITICAL, "Should be critical severity"
    print(f"✓ Registry correctly aggregated 3 blocks:")
    for hook in decision.blocking_hooks:
        print(f"  - {hook}")


async def main():
    print("Integration tests — Person 2 stack\n")
    await test_sink_isolation()
    print()
    await test_synthetic_end_to_end()
    print()
    await test_hook_registry_integration()
    print("\n✅ All integration tests passed")


if __name__ == "__main__":
    asyncio.run(main())
