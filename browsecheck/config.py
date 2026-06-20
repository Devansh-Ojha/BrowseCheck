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

    @property
    def is_browserbase(self) -> bool:
        return self.env == "BROWSERBASE"

    @property
    def sentry_enabled(self) -> bool:
        return bool(self.sentry_dsn)


@lru_cache
def get_settings() -> Settings:
    return Settings()
