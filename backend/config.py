"""Application settings, loaded from environment / .env."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # LLM
    OPENROUTER_API_KEY: str = ""

    # Data sources
    SERPAPI_KEY: str = ""
    GITHUB_TOKEN: str = ""

    # Ownership verification
    VERIFICATION_SECRET: str = "dev-insecure-change-me"
    GITHUB_OAUTH_CLIENT_ID: str = ""
    GITHUB_OAUTH_CLIENT_SECRET: str = ""

    # Email OTP delivery (blank SMTP_HOST => print codes to console)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@osint-auditor.local"

    # Infra / URLs
    REDIS_URL: str = "redis://localhost:6379/0"
    BACKEND_URL: str = "http://localhost:8000"
    FRONTEND_URL: str = "http://localhost:5173"

    # Shared constants
    USER_AGENT: str = "OSINT-Privacy-Auditor/1.0 (Personal privacy audit tool)"
    SESSION_TTL_SECONDS: int = 1800          # 30 min
    VERIFICATION_TTL_SECONDS: int = 900      # 15 min — how long a proof stays valid
    OTP_TTL_SECONDS: int = 600               # 10 min — how long a code is accepted
    MAX_PASTE_URLS: int = 50
    CRAWL_DELAY_SECONDS: float = 1.0


settings = Settings()
