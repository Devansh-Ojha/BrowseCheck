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
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from ..config import get_settings
from ..demo.synthetic import run_synthetic
from ..events.bus import memory_sink, sse_sink

app = FastAPI(title="BrowseCheck")
_settings = get_settings()
_DASHBOARD = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"
_last_scorecard: dict = {}
_tasks = set()  # ponytail: keep refs so tasks don't get GC'd


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_DASHBOARD)


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


@app.post("/run")
async def run(enforce: str = "on") -> JSONResponse:
    """Real traversal. TODO(P1): wire BrowserSession + control loop here.

    from ..browser.session import BrowserSession
    from ..controlloop.loop import run_traversal
    from ..hooks.factory import build_registry
    from ..tasks.demo_task import USER_TASK, demo_sites
    ... start session, run_traversal(enforce=enforce == "on", run_mode=...), close.
    """
    return JSONResponse(
        {"status": "not_wired", "hint": "see TODO(P1) in server/app.py:/run"},
        status_code=501,
    )


@app.get("/scorecard")
async def get_scorecard() -> JSONResponse:
    return JSONResponse(_last_scorecard or memory_sink.tally())


@app.post("/scorecard/run")
async def run_scorecard_endpoint() -> JSONResponse:
    """Compute the before/after tally. TODO(P2): call scorecard.runner once the
    control loop is live; for now returns the current MemorySink tally."""
    global _last_scorecard
    _last_scorecard = memory_sink.tally()
    return JSONResponse(_last_scorecard)
