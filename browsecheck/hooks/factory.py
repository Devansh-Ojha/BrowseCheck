"""Default registry assembly. OWNER: Shared.

Heroes first; deterministic checks bolt on. Toggle groups so Phase 1 can ship
with ONLY the prompt-injection hook, then breadth is one flag away.
"""

from __future__ import annotations

from .cert_ssl import CertSslHook
from .credential_phish import CredentialPhishHook
from .cross_site_carryover import CrossSiteCarryoverHook
from .download_inspect import DownloadInspectHook
from .intent_drift import IntentDriftHook
from .prompt_injection import PromptInjectionHook
from .registry import HookRegistry


def build_registry(
    *,
    prompt_injection: bool = True,
    intent_drift: bool = True,
    deterministic: bool = True,
    cross_site: bool = True,
) -> HookRegistry:
    reg = HookRegistry()
    if prompt_injection:
        reg.register(PromptInjectionHook())   # HERO — build first
    if intent_drift:
        reg.register(IntentDriftHook())       # HERO
    if cross_site:
        reg.register(CrossSiteCarryoverHook())  # catches multi-site injection carry-over
    if deterministic:
        reg.register(DownloadInspectHook())
        reg.register(CredentialPhishHook())
        reg.register(CertSslHook())
    return reg
