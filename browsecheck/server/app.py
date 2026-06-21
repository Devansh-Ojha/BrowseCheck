"""FastAPI app — dashboard backend. OWNER: Person 2.

Endpoints:
  GET  /                 -> the minimalist dashboard (static index.html)
  GET  /events           -> SSE stream of SecurityEvents (live log feed)
  POST /run/synthetic    -> emit the scripted demo run (no browser/LLM needed)
  POST /run?enforce=on|off -> real traversal via the control loop (P1 wiring)
  GET  /scorecard        -> last computed before/after tally
  POST /scorecard/run    -> run hooks-off + hooks-on, return the tally

Run:  uvicorn browsecheck.server.app:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from ..config import get_settings
from ..demo.synthetic import run_debug_naive, run_debug_normal, run_debug_protected, run_debug_suspicious, run_synthetic
from ..events.bus import memory_sink, sse_sink

app = FastAPI(title="BrowseCheck")
_settings = get_settings()
_ROOT = Path(__file__).resolve().parents[2]
_DASHBOARD = _ROOT / "dashboard" / "index.html"
_FIXTURES = _ROOT / "tests" / "fixtures"
_last_scorecard: dict = {}
_live_view: dict = {"url": "", "env": _settings.env}
_tasks: set = set()  # ponytail: keep refs so tasks don't get GC'd

# Recorded fallback — pre-baked result shown on stage if live scorecard fails.
_RECORDED_SCORECARD: dict = {
    "hooks-off": {"total": 2, "by_category": {"injection": 1, "credential": 1}},
    "hooks-on":  {"total": 2, "by_category": {"injection": 1, "credential": 1}},
    "recorded": True,
}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_DASHBOARD)


@app.get("/fixtures/{name}", response_model=None)
async def fixture(name: str) -> Response:
    """Serve the local attack/benign fixtures over HTTP so a real (cloud) browser
    can load them — e.g. via a public tunnel to this server."""
    target = (_FIXTURES / name).resolve()
    if _FIXTURES not in target.parents or not target.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(target)


@app.get("/live-view")
async def live_view() -> JSONResponse:
    """Browserbase live-view URL for the dashboard iframe (empty in LOCAL mode)."""
    return JSONResponse(_live_view)


@app.get("/events")
async def events() -> StreamingResponse:
    queue = sse_sink.subscribe()

    async def gen():
        try:
            # keep the connection open; heartbeat avoids proxies closing it
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {event.model_dump_json()}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            sse_sink.unsubscribe(queue)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/run/synthetic")
async def run_synthetic_demo() -> JSONResponse:
    task = asyncio.create_task(run_synthetic())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return JSONResponse({"status": "started", "mode": "synthetic"})


@app.post("/debug/naive")
async def debug_naive() -> JSONResponse:
    task = asyncio.create_task(run_debug_naive())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return JSONResponse({"status": "started", "mode": "debug-naive"})


@app.post("/debug/protected")
async def debug_protected() -> JSONResponse:
    task = asyncio.create_task(run_debug_protected())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return JSONResponse({"status": "started", "mode": "debug-protected"})


@app.post("/debug/normal")
async def debug_normal() -> JSONResponse:
    task = asyncio.create_task(run_debug_normal())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return JSONResponse({"status": "started", "mode": "debug-naive"})


@app.post("/debug/suspicious")
async def debug_suspicious() -> JSONResponse:
    task = asyncio.create_task(run_debug_suspicious())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return JSONResponse({"status": "started", "mode": "debug-protected"})


@app.post("/run")
async def run(enforce: str = "on") -> JSONResponse:
    """Real traversal via the Claude tool-use control loop (LOCAL or BROWSERBASE).

    Runs in the background and streams SecurityEvents to the dashboard over SSE.
    Requires ANTHROPIC_API_KEY (and BROWSERBASE_* when ENV=BROWSERBASE). Failures
    are surfaced as an `error` event on the feed rather than crashing the server.
    """
    run_mode = "hooks-on" if enforce == "on" else "hooks-off"
    _live_view["url"] = ""  # reset; refreshed once the session connects

    async def _run() -> None:
        from ..contracts import SecurityEvent, SiteRef, new_id
        from ..events.bus import event_bus

        session_id = new_id()
        try:
            from ..browser.session import BrowserSession
            from ..controlloop.loop import run_traversal
            from ..hooks.factory import build_registry
            from ..tasks.demo_task import USER_TASK, demo_sites

            protected = enforce == "on"
            session = BrowserSession(expose_hidden_surfaces=not protected)
            await session.start()
            if _settings.is_browserbase:
                from ..browser.replay import live_view_url
                _live_view["url"] = await live_view_url(session.session_id) or ""
            try:
                await run_traversal(
                    session, build_registry(),
                    user_task=USER_TASK, sites=demo_sites(),
                    enforce=protected, run_mode=run_mode,
                    session_id=session_id,
                )
            finally:
                await session.close()
        except Exception as exc:  # noqa: BLE001 — show the failure on the feed
            await event_bus.publish(SecurityEvent(
                session_id=session_id, run_mode=run_mode,
                site=SiteRef(url="", domain=""), kind="error",
                reason=f"run failed: {exc}",
            ))

    asyncio.create_task(_run())
    return JSONResponse({"status": "started", "mode": "live", "enforce": enforce})


@app.get("/scorecard")
async def get_scorecard() -> JSONResponse:
    return JSONResponse(_last_scorecard or memory_sink.tally() or _RECORDED_SCORECARD)


@app.post("/scorecard/run")
async def run_scorecard_endpoint() -> JSONResponse:
    """Kick off the before/after scorecard in the background. Poll GET /scorecard
    for the result. Falls back to the recorded scorecard if the live run fails."""
    async def _run() -> None:
        global _last_scorecard
        try:
            from ..scorecard.runner import run_scorecard
            from ..tasks.demo_task import USER_TASK, demo_sites
            _last_scorecard = await run_scorecard(USER_TASK, demo_sites())
        except Exception:  # noqa: BLE001 — use recorded fallback on stage
            _last_scorecard = _RECORDED_SCORECARD

    task = asyncio.create_task(_run())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return JSONResponse({"status": "started", "hint": "poll GET /scorecard for result"})
