"""Download inspection. OWNER: Person 2. Build after heroes work (fast/deterministic).

Blocks executables / suspicious downloads:
  - dangerous extension (.exe, .scr, .msi, ...)
  - double extension (invoice.pdf.exe)
  - MIME vs. extension mismatch
  - download not initiated by a user action
  - file type inappropriate for the site (e.g. .exe on a hackathon page)
"""

from __future__ import annotations

import os

from ..contracts import HookContext, HookResult, Severity
from .base import SecurityHook, _Timer

DANGEROUS_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".msi", ".dll", ".jar",
    ".js", ".vbs", ".ps1", ".sh", ".apk", ".dmg", ".pkg", ".deb",
}
# crude extension -> expected mime family
EXT_MIME = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".csv": "text/csv",
    ".txt": "text/plain",
    ".zip": "application/zip",
}


class DownloadInspectHook(SecurityHook):
    id = "download_inspect"
    category = "download"

    async def evaluate(self, ctx: HookContext) -> HookResult:
        with _Timer() as t:
            dl = ctx.page.pending_download
            if not dl:
                return self._allow("no download pending")

            filename = str(dl.get("filename", "")).lower()
            mime = str(dl.get("mime", "")).lower()
            user_initiated = bool(dl.get("user_initiated", True))
            _, ext = os.path.splitext(filename)
            parts = filename.split(".")

            # double extension, e.g. invoice.pdf.exe
            if len(parts) >= 3 and f".{parts[-1]}" in DANGEROUS_EXT:
                r = self._block(
                    f"double-extension executable download: {filename}",
                    severity=Severity.CRITICAL, filename=filename,
                )
            elif ext in DANGEROUS_EXT:
                r = self._block(
                    f"executable/suspicious download: {filename}",
                    severity=Severity.CRITICAL, filename=filename,
                )
            elif not user_initiated:
                r = self._block(
                    f"download started without user action: {filename}",
                    severity=Severity.HIGH, filename=filename,
                )
            elif ext in EXT_MIME and mime and not mime.startswith(EXT_MIME[ext].split("/")[0]):
                r = self._block(
                    f"MIME/extension mismatch: {filename} served as {mime}",
                    severity=Severity.HIGH, filename=filename, mime=mime,
                )
            else:
                r = self._allow("download looks benign", filename=filename)

        r.latency_ms = t.ms
        return r
