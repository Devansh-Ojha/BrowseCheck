"""Browserbase Live View URL helper for the dashboard iframe. OWNER: ohm.

The dashboard embeds the live session so the audience watches the agent browse.
Pass `BrowserSession.session_id` (set in `_create_browserbase_session()`).
TODO(P1): confirm the Browserbase debug endpoint/field for the live-view URL.
"""

from __future__ import annotations

import httpx

from ..config import Settings, get_settings

_BB_BASE = "https://api.browserbase.com/v1"


async def live_view_url(session_id: str, settings: Settings | None = None) -> str | None:
    settings = settings or get_settings()
    if not (session_id and settings.browserbase_api_key):
        return None
    # TODO(P1): confirm the correct Browserbase endpoint/field for the live view.
    url = f"{_BB_BASE}/sessions/{session_id}/debug"
    headers = {"X-BB-API-Key": settings.browserbase_api_key}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data.get("debuggerFullscreenUrl") or data.get("debuggerUrl")
    except Exception:  # noqa: BLE001
        return None
