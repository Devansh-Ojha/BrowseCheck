"""Deterministic extraction of injection 'surfaces'. OWNER: Person 1.

A surface is text that lives in the DOM but a human does not normally see — so
only the agent reads it — together with the ELEMENT it is stored in. This lets
the prompt-injection hook return the EXACT offending text and WHERE it is hidden,
deterministically, instead of hoping the LLM quotes it back. Covers the red
team's vectors: invisible CSS, image alt-text, HTML comments, and base64 blobs.
"""

from __future__ import annotations

import base64
import binascii
import re

# inline-style declarations that hide an element from humans
_HIDE_RE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*0"
    r"|opacity\s*:\s*0"
    r"|color\s*:\s*transparent"
    r"|text-indent\s*:\s*-?\d{3,}"
    r"|clip\s*:\s*rect"
    r"|(?:left|top)\s*:\s*-\d{3,}"
    r"|width\s*:\s*0",
    re.IGNORECASE,
)
# an element carrying an inline style + its inner content (non-nested case)
_STYLED_TAG = re.compile(
    r"<(\w+)[^>]*\bstyle\s*=\s*([\"'])(.*?)\2[^>]*>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)
_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_ALT = re.compile(r"<(\w+)[^>]*\b(alt|aria-label)\s*=\s*([\"'])(.*?)\3", re.IGNORECASE | re.DOTALL)
_STRIP_TAGS = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

# instruction-ish markers that make a surface "suspicious"
_MARKERS = re.compile(
    r"ignore (all|previous)|disregard|system message|system alert|you must"
    r"|re-?authenticate|sign ?in|log ?in|password|credentials|instructions"
    r"|click here|verify your|session (has )?expired|decode",
    re.IGNORECASE,
)


def _clean(text: str) -> str:
    return _WS.sub(" ", _STRIP_TAGS.sub(" ", text or "")).strip()


def _suspicious(text: str) -> bool:
    return bool(_MARKERS.search(text or ""))


def _truncate(s: str, n: int = 600) -> str:
    return s if len(s) <= n else s[:n] + "\u2026"


def extract_injection_surfaces(raw_html: str) -> list[dict]:
    """Return non-visible/suspicious surfaces as dicts:
    {kind, element, text, hidden, suspicious}."""
    out: list[dict] = []
    html = raw_html or ""

    # 1. elements hidden by inline CSS
    for m in _STYLED_TAG.finditer(html):
        tag, style, inner = m.group(1).lower(), m.group(3), m.group(4)
        if _HIDE_RE.search(style):
            text = _clean(inner)
            if text:
                out.append({
                    "kind": "hidden_css",
                    "element": f'<{tag} style="{_truncate(style.strip(), 120)}">',
                    "text": _truncate(text),
                    "hidden": True,
                    "suspicious": _suspicious(text),
                })

    # 2. HTML comments
    for m in _COMMENT.finditer(html):
        text = _clean(m.group(1))
        if text:
            out.append({
                "kind": "html_comment",
                "element": "<!-- comment -->",
                "text": _truncate(text),
                "hidden": True,
                "suspicious": _suspicious(text),
            })

    # 3. alt / aria-label text
    for m in _ALT.finditer(html):
        tag, attr, text = m.group(1).lower(), m.group(2).lower(), _clean(m.group(4))
        if text:
            out.append({
                "kind": "alt_text",
                "element": f'<{tag} {attr}="\u2026">',
                "text": _truncate(text),
                "hidden": True,
                "suspicious": _suspicious(text),
            })

    # 4. base64 blobs that decode to instruction-like text
    for m in _B64.finditer(html):
        token = m.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(c.isprintable() or c.isspace() for c in decoded)
        if len(decoded) >= 12 and printable / max(len(decoded), 1) > 0.9 and (
            " " in decoded or _suspicious(decoded)
        ):
            out.append({
                "kind": "base64",
                "element": f"base64 token ({token[:16]}\u2026)",
                "text": _truncate(decoded),
                "hidden": True,
                "suspicious": _suspicious(decoded),
            })

    return out


def pick_vulnerable(surfaces: list[dict]) -> dict | None:
    """The surface most likely to be the offending one: suspicious first, then
    the longest (most content)."""
    if not surfaces:
        return None
    suspicious = [s for s in surfaces if s.get("suspicious")]
    pool = suspicious or surfaces
    return max(pool, key=lambda s: len(s.get("text", "")))
