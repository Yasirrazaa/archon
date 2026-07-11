"""Archon configuration management using Pydantic Settings."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env files."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "archon"
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")

    # A2A Agent ports
    orchestrator_port: int = Field(default=9010, description="Orchestrator agent port")
    attacker_port: int = Field(default=9021, description="Attacker agent port")
    defender_port: int = Field(default=9020, description="Defender agent port")
    normal_user_port: int = Field(default=9022, description="Normal user agent port")

    # Agent timeouts
    agent_timeout_seconds: int = Field(default=300, description="Per-agent call timeout")
    normal_user_max_attempts: int = Field(default=3, description="Max attempts per normal user topic")

    # LLM Configuration
    openai_api_key: str | None = Field(default=None, description="OpenAI API key")
    openai_base_url: str | None = Field(default=None, description="OpenAI base URL (for proxies)")
    default_model: str = Field(default="gpt-4o-mini", description="Default LLM model")

    # Results
    results_dir: str = Field(default="results", description="Directory for battle results")

    # Security
    secret_key: str | None = Field(default=None, description="Secret key for signing")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def reset_settings() -> Settings:
    """Reset cached settings (useful for testing)."""
    get_settings.cache_clear()
    return get_settings()
