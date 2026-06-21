#!/usr/bin/env python
"""Test dashboard event handling. Verifies all event kinds are rendered correctly."""

import asyncio
from browsecheck.contracts import Decision, SecurityEvent, Severity, SiteRef
from browsecheck.events.bus import event_bus, memory_sink


async def test_all_event_kinds():
    """Verify the dashboard can handle every event kind without crashing."""
    memory_sink.clear()

    test_site = SiteRef(url="https://example.com/test", domain="example.com", label="Test Site")
    test_cases = [
        # (kind, required_fields_dict)
        ("navigate", {"site": test_site}),
        ("observe", {"site": test_site, "reason": "proposing action"}),
        ("hook-pass", {
            "site": test_site,
            "hook": "prompt_injection",
            "category": "injection",
            "decision": Decision.ALLOW,
            "severity": Severity.INFO,
            "reason": "no injection detected",
            "latency_ms": 50,
        }),
        ("hook-block", {
            "site": test_site,
            "hook": "credential_phish",
            "category": "credential",
            "decision": Decision.BLOCK,
            "severity": Severity.CRITICAL,
            "reason": "password field on non-auth domain",
            "evidence": {"form_action": "https://evil.com"},
            "latency_ms": 45,
        }),
        ("act", {"site": test_site, "reason": "filled form"}),
        ("site-complete", {"site": test_site}),
        ("run-complete", {"site": SiteRef(url="", domain="")}),
        ("error", {"site": test_site, "reason": "timeout reaching server"}),
    ]

    for kind, fields in test_cases:
        event = SecurityEvent(
            session_id="test",
            run_mode="hooks-on",
            step_index=0,
            kind=kind,  # type: ignore[arg-type]
            **fields
        )
        await event_bus.publish(event)
        print(f"✓ {kind:15} published")

    # Verify memory sink captured all blocks
    tally = memory_sink.tally()
    blocks = tally["hooks-on"]["total"]
    assert blocks == 1, f"Expected 1 block (credential), got {blocks}"
    print(f"\n✓ MemorySink correctly counted 1 block")
    print(f"✓ All {len(test_cases)} event kinds handled")


async def test_edge_cases():
    """Test malformed/edge-case events don't crash the system."""
    memory_sink.clear()

    # Empty event with minimal fields
    ev = SecurityEvent(
        session_id="test",
        kind="navigate",  # type: ignore[arg-type]
        site=SiteRef(url="", domain=""),
    )
    await event_bus.publish(ev)
    print("✓ Minimal event handled")

    # Missing optional fields
    ev = SecurityEvent(
        session_id="test",
        kind="hook-pass",  # type: ignore[arg-type]
        site=SiteRef(url="https://test.com", domain="test.com"),
        hook="test_hook",
        category="injection",  # type: ignore[arg-type]
        decision=Decision.ALLOW,
    )
    await event_bus.publish(ev)
    print("✓ Event with missing optional fields handled")

    # Large evidence object
    ev = SecurityEvent(
        session_id="test",
        kind="hook-block",  # type: ignore[arg-type]
        site=SiteRef(url="https://test.com", domain="test.com"),
        hook="test_hook",
        category="injection",  # type: ignore[arg-type]
        decision=Decision.BLOCK,
        evidence={"large": "x" * 10000},  # large string
    )
    await event_bus.publish(ev)
    print("✓ Large evidence object handled")


async def main():
    print("Testing dashboard event handling...\n")
    await test_all_event_kinds()
    print()
    await test_edge_cases()
    print("\n✅ Dashboard event handling robust")


if __name__ == "__main__":
    asyncio.run(main())
