"""Hook registry + pipeline. OWNER: Shared (P1 maintains).

Runs all enabled hooks in parallel and aggregates to ONE allow/block:
fail-closed (block if ANY hook blocks), max severity, combined reasons/evidence.
"""

from __future__ import annotations

import asyncio
import time

from ..contracts import (
    AggregateDecision,
    Decision,
    HookContext,
    HookResult,
    Severity,
)
from .base import SecurityHook

_SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class HookRegistry:
    def __init__(self) -> None:
        self._hooks: list[SecurityHook] = []

    def register(self, hook: SecurityHook) -> "HookRegistry":
        self._hooks.append(hook)
        return self

    def enabled_hooks(self) -> list[SecurityHook]:
        return [h for h in self._hooks if h.enabled]

    async def run(self, ctx: HookContext) -> AggregateDecision:
        hooks = self.enabled_hooks()
        results = await asyncio.gather(*(self._safe_eval(h, ctx) for h in hooks))

        blocking = [r for r in results if r.decision == Decision.BLOCK]
        decision = Decision.BLOCK if blocking else Decision.ALLOW
        severity = max(
            (r.severity for r in results),
            key=lambda s: _SEV_RANK[s],
            default=Severity.INFO,
        )
        return AggregateDecision(
            decision=decision,
            severity=severity,
            reasons=[r.reason for r in blocking],
            blocking_hooks=[r.hook for r in blocking],
            results=list(results),
        )

    async def _safe_eval(self, hook: SecurityHook, ctx: HookContext) -> HookResult:
        """A crashing/slow hook must never break the demo. On error we ALLOW but
        flag it (info) so the failure is visible without nuking the traversal.
        TODO(P1): decide if a hard LLM timeout should fail-closed instead."""
        start = time.perf_counter()
        try:
            result = await hook.evaluate(ctx)
            if not result.latency_ms:
                result.latency_ms = int((time.perf_counter() - start) * 1000)
            return result
        except Exception as exc:  # noqa: BLE001
            return HookResult(
                hook=getattr(hook, "id", "unknown"),
                category=getattr(hook, "category", "injection"),
                decision=Decision.ALLOW,
                severity=Severity.INFO,
                reason=f"hook error: {exc}",
                evidence={"error": str(exc)},
                latency_ms=int((time.perf_counter() - start) * 1000),
            )
