"""Cert / SSL validation. OWNER: Person 2. Build after heroes (deterministic).

Cheap pass/fail on certificate validity + domain match. Snapshot supplies
page.cert = {valid, cn, issuer}; this hook just interprets it.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..contracts import HookContext, HookResult, Severity
from .base import SecurityHook, _Timer


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _cn_matches(cn: str, host: str) -> bool:
    cn = (cn or "").lower().lstrip("*.")
    return bool(cn) and (host == cn or host.endswith("." + cn))


class CertSslHook(SecurityHook):
    id = "cert_ssl"
    category = "cert"

    async def evaluate(self, ctx: HookContext) -> HookResult:
        with _Timer() as t:
            host = ctx.page.domain or _host(ctx.page.url)

            if ctx.page.url.startswith("file://") or host in {"", "localhost", "127.0.0.1"}:
                r = self._allow("local/dev context — cert not enforced", host=host)
            elif not ctx.page.url.startswith("https://"):
                r = self._block("page is not served over HTTPS",
                                severity=Severity.MEDIUM, host=host)
            else:
                cert = ctx.page.cert
                if cert is None:
                    # TODO(P2): pull real cert from CDP/Browserbase. Until then,
                    # absence of cert info is not treated as a block.
                    r = self._allow("no cert info available (not enforced yet)",
                                    host=host)
                elif not cert.get("valid", False):
                    r = self._block("invalid TLS certificate",
                                    severity=Severity.HIGH, host=host, cert=cert)
                elif not _cn_matches(str(cert.get("cn", "")), host):
                    r = self._block("certificate CN does not match domain",
                                    severity=Severity.HIGH, host=host, cert=cert)
                else:
                    r = self._allow("valid certificate", host=host)

        r.latency_ms = t.ms
        return r
