from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    environment: Literal["development", "test", "production"] = "development"
    app_name: str = "AegisScan"
    database_url: str = "sqlite+aiosqlite:///./aegisscan.db"
    secret_key: str = "development-only-change-this-secret-key"
    frontend_origins: str = (
        "http://localhost:5173,"
        "https://aegis-scan-seven.vercel.app,"
        "https://aegis-scan-inky.vercel.app,"
        "https://adaptivescan-mocha.vercel.app,"
        "https://adaptivescan-jz67t5kn9-anmoliots-projects.vercel.app"
    )
    frontend_origin_regex: str | None = (
        r"https://(aegis-scan|adaptivescan)-[a-z0-9-]+\.vercel\.app"
    )
    registration_enabled: bool = True
    default_admin_enabled: bool = True
    default_admin_email: str = "admin@test.com"
    default_admin_password: str = "password12"
    default_admin_display_name: str = "Admin"
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    scan_timeout_seconds: float = 10.0
    scan_max_requests: int = 30
    scan_max_response_bytes: int = 1_000_000
    scan_concurrency: int = 2
    scan_user_agent: str = "AegisScan/1.0 (authorized-security-assessment)"

    metrics_enabled: bool = True
    log_format: Literal["json", "text"] = "json"

    @property
    def origins(self) -> list[str]:
        return [value.strip().rstrip("/") for value in self.frontend_origins.split(",") if value.strip()]

    @property
    def docs_enabled(self) -> bool:
        return self.environment != "production"

    @model_validator(mode="after")
    def production_safety(self):
        if self.environment == "production":
            if len(self.secret_key) < 48 or "change" in self.secret_key.lower():
                raise ValueError("SECRET_KEY must be a strong value of at least 48 characters")
            if not self.database_url.startswith(("postgresql+asyncpg://", "postgresql://")):
                raise ValueError("Production requires PostgreSQL")
            if (not self.origins and not self.frontend_origin_regex) or "*" in self.origins:
                raise ValueError("Production FRONTEND_ORIGINS or FRONTEND_ORIGIN_REGEX must be explicit")
            if not self.cookie_secure:
                raise ValueError("Production cookies must be secure")
            if self.default_admin_enabled:
                raise ValueError("Production must not enable the default admin account")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
