"""Anthropic client wrapper for the two hero hooks.

OWNER: Person 1.

Uses Claude tool-use to force structured JSON output so hook results parse
reliably. Hooks call `classify(...)` with a system prompt + the SECURITY_TOOL
schema and get back a dict: {decision, severity, reason, evidence}.
"""

from __future__ import annotations

from typing import Any

from ..config import Settings, get_settings

# Tool schema shared by both hero hooks. The LLM MUST return exactly this shape.
SECURITY_TOOL: dict[str, Any] = {
    "name": "report_security_decision",
    "description": "Report whether the proposed agent action is safe to execute.",
    "input_schema": {
        "type": "object",
        "properties": {
            "decision": {"type": "string", "enum": ["allow", "block"]},
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
            },
            "reason": {
                "type": "string",
                "description": "One concise sentence a security analyst would write.",
            },
            "evidence": {
                "type": "object",
                "description": "Specific quotes/selectors/markers that justify the decision.",
                "additionalProperties": True,
            },
        },
        "required": ["decision", "severity", "reason"],
    },
}


class LLMProvider:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client = None  # lazy so import never requires a key

    def _client_or_raise(self):
        if self._client is None:
            from anthropic import AsyncAnthropic

            if not self.settings.anthropic_api_key:
                raise RuntimeError("ANTHROPIC_API_KEY is not set")
            self._client = AsyncAnthropic(api_key=self.settings.anthropic_api_key)
        return self._client

    async def classify(
        self, *, system: str, user: str, max_tokens: int = 1024
    ) -> dict[str, Any]:
        """Return the tool-use payload as a dict. Raises on transport errors;
        callers (hooks) are responsible for the timeout/fallback policy."""
        client = self._client_or_raise()
        resp = await client.messages.create(
            model=self.settings.anthropic_model,
            max_tokens=max_tokens,
            system=system,
            tools=[SECURITY_TOOL],
            tool_choice={"type": "tool", "name": SECURITY_TOOL["name"]},
            messages=[{"role": "user", "content": user}],
        )
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use":
                return dict(block.input)
        return {}


_provider: LLMProvider | None = None


def get_provider() -> LLMProvider:
    global _provider
    if _provider is None:
        _provider = LLMProvider()
    return _provider
