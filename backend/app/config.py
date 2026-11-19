from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://dera:dera_dev_only@postgres:5432/dera"
    redis_url: str = "redis://redis:6379/0"
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    scan_timeout_seconds: float = 10.0
    scan_rate_limit: str = "10/minute"
    environment: str = "development"

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
