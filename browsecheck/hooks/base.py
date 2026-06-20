"""Common hook interface. OWNER: Shared (Phase-0 contract).

Every hook implements evaluate(ctx) -> HookResult against
(pageContent, proposedAction, userTask). Adding a new hook is one class + one
registry.register() call.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from ..contracts import Decision, HookCategory, HookContext, HookResult, Severity


class SecurityHook(ABC):
    id: str
    category: HookCategory
    enabled: bool = True

    @abstractmethod
    async def evaluate(self, ctx: HookContext) -> HookResult:
        """Return allow/block for the proposed action. MUST NOT mutate the page
        or perform the action — hooks only inspect and decide."""
        raise NotImplementedError

    # -- helpers so concrete hooks stay terse ------------------------------- #
    def _allow(self, reason: str = "", **evidence) -> HookResult:
        return HookResult(
            hook=self.id, category=self.category, decision=Decision.ALLOW,
            severity=Severity.INFO, reason=reason, evidence=evidence,
        )

    def _block(
        self, reason: str, severity: Severity = Severity.HIGH, **evidence
    ) -> HookResult:
        return HookResult(
            hook=self.id, category=self.category, decision=Decision.BLOCK,
            severity=severity, reason=reason, evidence=evidence,
        )


class _Timer:
    """`with _Timer() as t: ...` then read t.ms."""

    def __enter__(self) -> "_Timer":
        self._start = time.perf_counter()
        self.ms = 0
        return self

    def __exit__(self, *exc) -> None:
        self.ms = int((time.perf_counter() - self._start) * 1000)
