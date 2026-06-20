"""Stagehand session wrapper — the LOCAL<->BROWSERBASE seam. OWNER: Person 1.

This is the #1 RISK surface (validate in first 2h): confirm Stagehand Python
exposes observe() returning an inspectable proposal and act() that runs ONLY
that proposal, so the hook pipeline can gate BEFORE execution. We never call the
autonomous agent() loop.

Method names below follow the expected Stagehand Python API; adjust once the
spike confirms the real surface.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..config import Settings, get_settings
from ..contracts import ObservedAction, PageSnapshot, SiteRef


def _domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


class BrowserSession:
    """Thin wrapper around Stagehand so the rest of the app is SDK-agnostic."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._sh = None          # Stagehand instance
        self.page = None         # Stagehand page
        self.session_id: str = ""

    async def start(self) -> None:
        """Initialise Stagehand for LOCAL or BROWSERBASE.

        TODO(P1): confirm exact StagehandConfig fields for the installed version.
        """
        from stagehand import Stagehand, StagehandConfig

        config = StagehandConfig(
            env="BROWSERBASE" if self.settings.is_browserbase else "LOCAL",
            api_key=self.settings.browserbase_api_key or None,
            project_id=self.settings.browserbase_project_id or None,
            model_name=self.settings.anthropic_model,
            model_api_key=self.settings.anthropic_api_key or None,
        )
        self._sh = Stagehand(config)
        await self._sh.init()
        self.page = self._sh.page
        # TODO(P1): capture the real Browserbase session id for the live-view URL.
        self.session_id = getattr(self._sh, "session_id", "") or ""

    async def goto(self, url: str) -> None:
        await self.page.goto(url)

    async def observe(self, instruction: str) -> list[ObservedAction]:
        """Return PROPOSED actions WITHOUT executing them."""
        results = await self.page.observe(instruction)
        actions: list[ObservedAction] = []
        for r in results or []:
            actions.append(
                ObservedAction(
                    description=getattr(r, "description", str(r)),
                    method=getattr(r, "method", "act"),
                    selector=getattr(r, "selector", None),
                    args=list(getattr(r, "arguments", []) or []),
                )
            )
        # keep raw handles so act() can replay the EXACT observed action
        self._last_observed = results
        return actions

    async def act(self, index: int = 0) -> None:
        """Execute ONLY the previously observed action at `index`. Called solely
        after the aggregate decision is allow."""
        await self.page.act(self._last_observed[index])

    async def snapshot(self, site: SiteRef | None = None) -> PageSnapshot:
        """Capture what hooks are allowed to inspect.

        TODO(P1): wire pending_download (CDP/Playwright download event) and cert
        info (CDP Security domain) so the deterministic hooks have real inputs.
        """
        url = self.page.url
        try:
            rendered = await self.page.evaluate("() => document.body.innerText")
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
        if self._sh is not None:
            await self._sh.close()
