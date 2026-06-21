from __future__ import annotations

import re
from urllib.parse import quote, urljoin, urlparse

from ..contracts import SecurityEvent, SiteRef
from ..events.bus import event_bus
from ..hooks._injection_surfaces import extract_injection_surfaces

_LOGIN_RE = re.compile(r"(?:^|[\s'\"`>])(/login\b[^\s'\"`<]*)", re.IGNORECASE)
_DEMO_LOGIN_HTML = """<!doctype html><html><head><title>BrowseCheck Demo Login</title><style>body{margin:0;background:#050606;color:#fff;font-family:Inter,Arial,sans-serif;display:grid;place-items:center;min-height:100vh}.card{width:360px;border:1px solid rgba(255,255,255,.14);border-radius:24px;background:linear-gradient(135deg,rgba(255,255,255,.12),rgba(255,255,255,.04));padding:28px;box-shadow:0 30px 80px rgba(0,0,0,.55)}label{display:block;margin-top:14px;color:#bbb;font-size:13px}input{width:100%;box-sizing:border-box;margin-top:6px;border:1px solid rgba(255,255,255,.16);border-radius:12px;background:#111;color:#fff;padding:12px}button{width:100%;margin-top:18px;border:0;border-radius:12px;background:#fda4af;color:#111;font-weight:700;padding:12px}</style></head><body><main class=card><h1>Session verification</h1><p>This stable demo login page replaces the flaky red-team /login endpoint.</p><label>Email<input aria-label=Email placeholder=Email name=email></label><label>Password<input aria-label=Password placeholder=Password name=password type=password></label><button>Login</button></main></body></html>"""


async def run_naive_demo(session, sites: list[SiteRef], *, session_id: str) -> None:
    async def emit(**kw) -> None:
        await event_bus.publish(SecurityEvent(session_id=session_id, run_mode="hooks-off", **kw))

    for original in sites:
        site = original
        if not site.domain:
            site = SiteRef(
                url=site.url,
                domain=(urlparse(site.url).hostname or "").lower(),
                label=site.label,
            )
        await session.goto(site.url)
        await emit(kind="navigate", site=site)

        await emit(kind="observe", step_index=0, site=site, reason="read the current page")
        page_text = await session.execute_tool("read_page", {})
        await emit(kind="act", step_index=0, site=site, reason="read the current page")

        login_path = await _login_path(session, page_text)
        if not login_path:
            await emit(
                kind="observe",
                step_index=1,
                site=site,
                reason="final message: no login or verification step found",
            )
            await emit(
                kind="act",
                step_index=1,
                site=site,
                reason="final message: no login or verification step found",
            )
            await emit(kind="site-complete", site=site)
            continue

        login_url = urljoin(session.page.url, login_path)
        stable_login_url = _stable_login_url(login_url)
        await emit(
            kind="observe",
            step_index=1,
            site=site,
            reason=f"naively follows page instruction: navigate to {login_url}",
        )
        nav_result = await session.execute_tool("navigate", {"url": stable_login_url})
        await emit(
            kind="act",
            step_index=1,
            site=site,
            reason=f"loaded stable BrowseCheck demo login page instead of flaky endpoint: {login_url}",
        )

        await emit(kind="observe", step_index=2, site=site, reason="read the login page")
        await session.execute_tool("read_page", {})
        await emit(kind="act", step_index=2, site=site, reason="read the login page")

        await _try_fill(session, emit, site, 3, "Email", "demo@browsecheck.local")
        await _try_fill(session, emit, site, 4, "Password", "not-a-real-password")
        await _try_click_login(session, emit, site, 5)
        await emit(kind="site-complete", site=site)

    await emit(kind="run-complete", site=SiteRef(url="", domain=""))


def _stable_login_url(original_login_url: str) -> str:
    html = _DEMO_LOGIN_HTML.replace("flaky red-team /login endpoint", f"flaky red-team endpoint: {original_login_url}")
    return "data:text/html;charset=utf-8," + quote(html)


async def _login_path(session, page_text: str) -> str:
    match = _LOGIN_RE.search(page_text or "")
    if match:
        return match.group(1)

    snap = await session.snapshot()
    for surface in extract_injection_surfaces(snap.raw_html):
        text = surface.get("text") or ""
        match = _LOGIN_RE.search(text)
        if match:
            return match.group(1)
    return ""


async def _try_fill(session, emit, site: SiteRef, step: int, field: str, value: str) -> None:
    await emit(kind="observe", step_index=step, site=site, reason=f"fill '{field}' with demo credential")
    result = await session.execute_tool("fill", {"field": field, "value": value})
    await emit(kind="act", step_index=step, site=site, reason=result)


async def _try_click_login(session, emit, site: SiteRef, step: int) -> None:
    for label in ("Log in", "Login", "Sign in", "Continue", "Submit"):
        await emit(kind="observe", step_index=step, site=site, reason=f"click '{label}'")
        result = await session.execute_tool("click", {"text": label})
        await emit(kind="act", step_index=step, site=site, reason=result)
        if not result.startswith("click failed"):
            return
        step += 1
