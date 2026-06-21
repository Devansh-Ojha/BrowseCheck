"""Browser executor: the agent loop's hands. OWNER: Person 1.

We OWN the agent loop (see `controlloop/loop.py`) via the Anthropic tool-use API
and execute its proposed tool calls here, over CDP with Playwright — connected to
a Browserbase session (demo) or local Chromium (dev). Browserbase treats agent
security as a user-level concern, so the gate lives entirely in our hook
pipeline; this module only EXECUTES actions the pipeline has already allowed.

`BROWSER_TOOLS` is the action surface we expose to Claude. Each tool maps to a
deterministic Playwright operation, so the set of things the agent can do — and
thus the set of things we must gate — is fixed and inspectable.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import Settings, get_settings
from ..contracts import PageSnapshot, SiteRef

_BB_BASE = "https://api.browserbase.com/v1"


def _domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


# The fixed action surface handed to Claude. `finish` is the agent's message to
# the USER — it is the relay/social-engineering surface, so the loop gates it
# exactly like any browser action before delivering it.
BROWSER_TOOLS: list[dict[str, Any]] = [
    {
        "name": "navigate",
        "description": "Navigate the browser to a URL.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "read_page",
        "description": "Return the visible text of the current page so you can decide what to do next.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "click",
        "description": "Click an element identified by its visible text, label, or role name.",
        "input_schema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "fill",
        "description": "Type a value into a form field identified by its label or placeholder.",
        "input_schema": {
            "type": "object",
            "properties": {
                "field": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["field", "value"],
        },
    },
    {
        "name": "finish",
        "description": "Finish the task and return your final message to the user.",
        "input_schema": {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
        },
    },
]


class BrowserSession:
    """Playwright/CDP executor. SDK-agnostic to the rest of the app."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._pw = None
        self._browser = None
        self._context = None
        self.page = None
        self.session_id: str = ""

    def tool_schemas(self) -> list[dict[str, Any]]:
        return BROWSER_TOOLS

    async def start(self) -> None:
        """Connect to Browserbase over CDP (demo) or launch local Chromium (dev)."""
        from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()
        if self.settings.is_browserbase:
            connect_url = await self._create_browserbase_session()
            self._browser = await self._pw.chromium.connect_over_cdp(connect_url)
            self._context = (
                self._browser.contexts[0]
                if self._browser.contexts
                else await self._browser.new_context()
            )
        else:
            self._browser = await self._pw.chromium.launch(headless=True)
            self._context = await self._browser.new_context()
        self.page = (
            self._context.pages[0]
            if self._context.pages
            else await self._context.new_page()
        )

    async def _create_browserbase_session(self) -> str:
        """Create a Browserbase session and return its CDP connect URL.

        TODO(P1): confirm the exact response field for the CDP endpoint
        (`connectUrl`) against the installed Browserbase API version.
        """
        if not (self.settings.browserbase_api_key and self.settings.browserbase_project_id):
            raise RuntimeError(
                "BROWSERBASE_API_KEY and BROWSERBASE_PROJECT_ID are required for ENV=BROWSERBASE"
            )
        headers = {
            "X-BB-API-Key": self.settings.browserbase_api_key,
            "Content-Type": "application/json",
        }
        payload = {"projectId": self.settings.browserbase_project_id}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{_BB_BASE}/sessions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        self.session_id = data.get("id", "")
        connect_url = data.get("connectUrl")
        if not connect_url:
            raise RuntimeError(f"Browserbase session has no connectUrl: {data}")
        return connect_url

    # --- executor: runs ONLY actions the hook pipeline already allowed -------- #
    async def execute_tool(self, name: str, args: dict[str, Any]) -> str:
        if name == "navigate":
            return await self.goto(args.get("url", ""))
        if name == "read_page":
            snap = await self.snapshot()
            return snap.rendered_text[:6000] or "(page has no visible text)"
        if name == "click":
            return await self._click(args.get("text") or args.get("selector") or "")
        if name == "fill":
            return await self._fill(args.get("field", ""), args.get("value", ""))
        # `finish` is handled by the control loop (it ends the run + is gated as
        # the relay surface), so it should never reach here.
        return f"unknown tool: {name}"

    async def goto(self, url: str) -> str:
        if not url:
            return "navigate: missing url"
        await self.page.goto(url, wait_until="domcontentloaded")
        return f"navigated to {self.page.url}"

    async def _click(self, target: str) -> str:
        if not target:
            return "click: missing target"
        try:
            loc = self.page.get_by_role("button", name=target)
            if await loc.count() == 0:
                loc = self.page.get_by_text(target, exact=False)
            await loc.first.click(timeout=5000)
            return f"clicked '{target}'"
        except Exception as exc:  # noqa: BLE001
            return f"click failed for '{target}': {exc}"

    async def _fill(self, field: str, value: str) -> str:
        if not field:
            return "fill: missing field"
        try:
            loc = self.page.get_by_label(field)
            if await loc.count() == 0:
                loc = self.page.get_by_placeholder(field)
            await loc.first.fill(value, timeout=5000)
            return f"filled '{field}'"
        except Exception as exc:  # noqa: BLE001
            return f"fill failed for '{field}': {exc}"

    async def snapshot(self, site: SiteRef | None = None) -> PageSnapshot:
        """Capture what hooks inspect.

        TODO(P1, task B): also extract hidden-element text, all `alt` attributes,
        and HTML comments, and decode base64 tokens (the red-team injection
        surfaces). TODO(P1): wire pending_download (Playwright download event) and
        cert info (CDP Security domain) for the deterministic hooks.
        """
        url = self.page.url
        try:
            rendered = await self.page.evaluate(
                "() => document.body ? document.body.innerText : ''"
            )
        except Exception:  # noqa: BLE001
            rendered = ""
        try:
            html = await self.page.content()
        except Exception:  # noqa: BLE001
            html = ""
        return PageSnapshot(
            url=url,
            domain=_domain(url),
            rendered_text=rendered or "",
            raw_html=html or "",
            pending_download=None,  # TODO(P1)
            cert=None,              # TODO(P1)
        )

    async def close(self) -> None:
        try:
            if self._browser is not None:
                await self._browser.close()
        finally:
            if self._pw is not None:
                await self._pw.stop()
