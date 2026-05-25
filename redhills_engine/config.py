"""Global environment validation via Pydantic Settings."""

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class EngineSettings(BaseSettings):
    """Validated configuration for all Red Hills Engine services."""

    DATABASE_URL: str = Field(
        ...,
        description="Async PostgreSQL connection string (postgresql+asyncpg://...)",
    )
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for pub/sub and caching",
    )
    OPENAI_API_KEY: str = Field(
        default="",
        description="OpenAI API key for payload generation",
    )
    ANTHROPIC_API_KEY: str = Field(
        default="",
        description="Anthropic API key for payload generation",
    )
    EGRESS_MONITOR_DOMAIN: str = Field(
        default="egress.redhills.local",
        description="Domain where the OOB egress monitor is reachable",
    )
    MAX_CONCURRENT_SCANS: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum number of parallel scan workers",
    )
    EGRESS_MONITOR_PORT: int = Field(
        default=9090,
        description="Port for the egress monitor FastAPI server",
    )
    ORCHESTRATOR_POLL_INTERVAL: float = Field(
        default=2.0,
        description="Seconds between orchestrator queue polls",
    )
    MAX_MUTATION_RETRIES: int = Field(
        default=15,
        description="Maximum mutation attempts per attack category",
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level for all services",
    )

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith(("postgresql+asyncpg://", "sqlite+aiosqlite://")):
            raise ValueError(
                "DATABASE_URL must use an async driver "
                "(postgresql+asyncpg:// or sqlite+aiosqlite://)"
            )
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


def get_settings() -> EngineSettings:
    """Construct and cache validated settings from environment."""
    return EngineSettings()  # type: ignore[call-arg]
