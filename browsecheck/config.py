"""Environment / settings + the LOCAL<->BROWSERBASE seam.

OWNER: Shared (P1 maintains; P2 reads sentry_enabled / port).
"""

from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


class Settings:
    def __init__(self) -> None:
        self.env: str = os.getenv("ENV", "LOCAL").upper()  # LOCAL | BROWSERBASE
        self.browserbase_api_key: str = os.getenv("BROWSERBASE_API_KEY", "")
        self.browserbase_project_id: str = os.getenv("BROWSERBASE_PROJECT_ID", "")
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
        self.anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        self.sentry_dsn: str = os.getenv("SENTRY_DSN", "")
        self.port: int = int(os.getenv("PORT", "8000"))
        # Demo: the poisoned page the cloud browser must be able to REACH.
        # REDTEAM_URL = the red team's hosted portal (preferred). FIXTURE_BASE_URL
        # = a public base (e.g. a tunnel to this server) used to serve our own
        # tests/fixtures when no red-team URL exists yet.
        self.redteam_url: str = os.getenv("REDTEAM_URL", "")
        self.fixture_base_url: str = os.getenv("FIXTURE_BASE_URL", "")
        # Scenario 2: the eBay listing the payment agent visits. A fair match for
        # the phone request whose description/reviews hide a malicious link.
        self.shopping_url: str = os.getenv("SHOPPING_URL", "")

    @property
    def is_browserbase(self) -> bool:
        return self.env == "BROWSERBASE"

    @property
    def sentry_enabled(self) -> bool:
        return bool(self.sentry_dsn)


@lru_cache
def get_settings() -> Settings:
    return Settings()
