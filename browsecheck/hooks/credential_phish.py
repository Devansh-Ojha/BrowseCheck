"""Credential / phishing check. OWNER: Person 2. Build after heroes (deterministic).

Flags credential-harvesting pages (we FLAG the page, never store credentials):
  - password field on a domain that isn't the legitimate auth provider
  - <form action> / network destination not matching the real OAuth domain
  - a static form mimicking an OAuth screen instead of a real redirect to
    accounts.google.com / github.com / etc.

This is the hook that nails the fake Berkeley hackathon portal in the demo.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..contracts import HookContext, HookResult, Severity
from .base import SecurityHook, _Timer

# domains that are allowed to ask for a password / run OAuth
LEGIT_AUTH_DOMAINS = {
    "accounts.google.com", "login.microsoftonline.com", "github.com",
    "appleid.apple.com", "auth0.com", "okta.com",
}

_PWD_INPUT = re.compile(r"<input[^>]*type=['\"]?password['\"]?", re.IGNORECASE)
_FORM_ACTION = re.compile(r"<form[^>]*action=['\"]([^'\"]+)['\"]", re.IGNORECASE)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


class CredentialPhishHook(SecurityHook):
    id = "credential_phish"
    category = "credential"

    async def evaluate(self, ctx: HookContext) -> HookResult:
        with _Timer() as t:
            html = ctx.page.raw_html or ""
            page_host = ctx.page.domain or _host(ctx.page.url)

            has_password = bool(_PWD_INPUT.search(html))
            if not has_password:
                return self._allow("no password field", host=page_host)

            # password field present on a non-auth-provider domain
            if page_host not in LEGIT_AUTH_DOMAINS:
                # check where the form would post
                action_hosts = [
                    _host(m) for m in _FORM_ACTION.findall(html) if _host(m)
                ]
                mismatched = [
                    h for h in action_hosts
                    if h and h != page_host and h not in LEGIT_AUTH_DOMAINS
                ]
                r = self._block(
                    "password field on a non-auth domain (likely phishing)",
                    severity=Severity.CRITICAL,
                    page_host=page_host,
                    form_action_hosts=action_hosts,
                    mismatched_hosts=mismatched,
                )
            else:
                r = self._allow("password field on legitimate auth domain",
                                 host=page_host)

        r.latency_ms = t.ms
        return r
