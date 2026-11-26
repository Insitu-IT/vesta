"""
Configuration management using pydantic-settings
"""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Application
    app_name: str = "vnbui"
    environment: str = "development"
    debug: bool = False

    # Normal product execution must never silently manufacture backup success.
    # The public demo has its own isolated API and data, not a backup executor.
    use_real_backup_executor: bool = True

    @field_validator("use_real_backup_executor")
    @classmethod
    def require_real_backup_executor(cls, value):
        if not value:
            raise ValueError(
                "USE_REAL_BACKUP_EXECUTOR=false is unsupported; "
                "normal installations require real backup execution"
            )
        return value

    # Empty-database bootstrap. The password is read from a mounted file so it
    # never has to cross a shell argument or live in the process environment.
    initial_admin_username: Optional[str] = None
    initial_admin_password_file: Optional[str] = None

    # Public evaluator sandbox. This is an OSS application mode, independent of
    # commercial organization/RLS features. Middleware fails closed around its
    # dedicated API when enabled.
    demo_mode: bool = False
    demo_session_idle_minutes: int = 60
    demo_session_absolute_minutes: int = 120
    demo_cookie_secure: bool = True
    demo_source_requests_per_minute: int = 120
    demo_session_requests_per_minute: int = 60
    # Deliberately unset: the infrastructure capacity decision must supply it.
    demo_max_sessions: int = 0
    demo_max_groups: int = 8
    demo_max_schedules: int = 7
    demo_max_backups: int = 27
    demo_max_restores: int = 11
    demo_max_activity: int = 50

    # Offline registration trust is operator-provisioned; this URL is display-only.
    license_keys_file: str = "/etc/vnbui/license-keys.json"
    license_registration_url: str = "https://vestabackup.com/portal/licensing"

    # Database
    database_url: str = "postgresql://vnbui:vnbui@localhost:5432/vnbui"

    # JWT authentication is NOT configured here. It lives in deps.py, which is
    # what the application actually reads. These fields existed here too, unread,
    # with a literal default -- a second answer to a question that already had
    # one, and the reason two modules imported the signing key from a module that
    # never defined it. One owner, deliberately.

    # Orchestrator → Agent Authentication (key sent to agents)
    orchestrator_to_agent_key: Optional[str] = (
        None  # Must match ORCHESTRATOR_API_KEY on agents
    )

    # CORS
    allowed_origins: str = "http://localhost:3000,http://localhost:8080"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: Optional[str] = None

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_storage: str = "memory://"  # or redis://localhost:6379

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @property
    def allowed_origins_list(self) -> List[str]:
        """Parse allowed origins from comma-separated string"""
        return [
            origin.strip()
            for origin in self.allowed_origins.split(",")
            if origin.strip()
        ]

    @property
    def redis_url(self) -> str:
        """Build Redis URL from components"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}"
        return f"redis://{self.redis_host}:{self.redis_port}"

    @property
    def async_database_url(self) -> str:
        """Convert PostgreSQL URL to async version"""
        return self.database_url.replace("postgresql://", "postgresql+asyncpg://")


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Global settings instance
settings = get_settings()
