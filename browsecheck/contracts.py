"""FROZEN Phase-0 contracts shared by both engineers.

OWNER: Shared (agreed before any other work; change only by mutual consent).

Two contracts live here:
  1. Hook contract  -> HookContext (input)  / HookResult (output)
  2. Event contract -> SecurityEvent (everything the bus, dashboard, Sentry consume)

ohm (control loop + hero hooks) and Person 2 (events + dashboard + scorecard
+ deterministic hooks) both import from this module and nothing else of each other's.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# One of the FINAL hook categories. Do not add others.
HookCategory = Literal["injection", "intent", "download", "credential", "cert"]

EventKind = Literal[
    "navigate",        # agent navigated to a site
    "observe",         # observe() produced a proposed action
    "hook-pass",       # a single hook allowed the action
    "hook-block",      # a single hook blocked the action
    "act",             # action executed (only after aggregate allow)
    "site-complete",   # finished a site
    "run-complete",    # finished the traversal
    "error",           # something went wrong
]

RunMode = Literal["hooks-on", "hooks-off"]


def now_ms() -> float:
    return time.time() * 1000.0


def new_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- #
# Hook contract
# --------------------------------------------------------------------------- #
class ObservedAction(BaseModel):
    """A proposed action distilled from Stagehand observe() — NOT yet executed."""

    description: str
    method: str = "act"                       # act | click | fill | goto | download ...
    selector: Optional[str] = None
    args: list[Any] = Field(default_factory=list)
    target_url: Optional[str] = None          # for navigation/download actions


class PageSnapshot(BaseModel):
    """Everything a hook is allowed to inspect about the current page."""

    url: str
    domain: str
    rendered_text: str = ""                   # visible text
    raw_html: str = ""                        # for hidden-vs-rendered diff, HTML comments
    pending_download: Optional[dict[str, Any]] = None  # {filename, mime, user_initiated}
    cert: Optional[dict[str, Any]] = None              # {valid, cn, issuer}


class HookContext(BaseModel):
    """Input to every hook's evaluate()."""

    user_task: str
    proposed_action: ObservedAction
    page: PageSnapshot
    step_index: int
    session_id: str


class HookResult(BaseModel):
    """Output of every hook's evaluate()."""

    hook: str
    category: HookCategory
    decision: Decision
    severity: Severity = Severity.INFO
    reason: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int = 0


class AggregateDecision(BaseModel):
    """Registry output: the combined verdict for one step."""

    decision: Decision
    severity: Severity
    reasons: list[str] = Field(default_factory=list)
    blocking_hooks: list[str] = Field(default_factory=list)
    results: list[HookResult] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Event contract
# --------------------------------------------------------------------------- #
class SiteRef(BaseModel):
    url: str
    domain: str = ""
    label: Optional[str] = None


class SecurityEvent(BaseModel):
    """The single event type emitted on the bus. Sentry + dashboard + scorecard
    all consume exactly this. SentrySink is a pure mapping of these fields."""

    id: str = Field(default_factory=new_id)
    ts: float = Field(default_factory=now_ms)
    session_id: str
    run_mode: RunMode = "hooks-on"
    step_index: int = 0
    site: SiteRef
    kind: EventKind

    # populated for hook-pass / hook-block
    hook: Optional[str] = None
    category: Optional[str] = None
    decision: Optional[Decision] = None
    severity: Optional[Severity] = None
    reason: Optional[str] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    latency_ms: Optional[int] = None

    @classmethod
    def from_hook_result(
        cls, result: HookResult, *, session_id: str, run_mode: RunMode,
        step_index: int, site: SiteRef,
    ) -> "SecurityEvent":
        return cls(
            session_id=session_id,
            run_mode=run_mode,
            step_index=step_index,
            site=site,
            kind="hook-block" if result.decision == Decision.BLOCK else "hook-pass",
            hook=result.hook,
            category=result.category,
            decision=result.decision,
            severity=result.severity,
            reason=result.reason,
            evidence=result.evidence,
            latency_ms=result.latency_ms,
        )
