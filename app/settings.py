from functools import lru_cache
from os import environ

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database connections (required)
    GRAPH_DB_URI: str = Field(..., alias="GRAPH_DB_URI")
    GRAPH_DB_USER: str = Field(..., alias="GRAPH_DB_USER")
    GRAPH_DB_PASSWORD: str = Field(..., alias="GRAPH_DB_PASSWORD")
    VULN_DB_URI: str = Field(..., alias="VULN_DB_URI")

    # GitHub API Key (required)
    GITHUB_GRAPHQL_API_KEY: str = Field(..., alias="GITHUB_GRAPHQL_API_KEY")

    # JWT secrets (required)
    JWT_ACCESS_SECRET_KEY: str = Field(..., alias="JWT_ACCESS_SECRET_KEY")

    # Application settings (safe defaults)
    DOCS_URL: str | None = Field(None, alias="DOCS_URL")
    SERVICES_ALLOWED_ORIGINS: list[str] = Field(["*"], alias="SERVICES_ALLOWED_ORIGINS")
    ALGORITHM: str = Field("HS256", alias="ALGORITHM")

    # VEX Configuration
    VEX_VULNERABILITY_IMPACT_WEIGHT: float = 0.7
    VEX_REACHABLE_CODE_PRIORITY_BONUS: float = 1.0
    VEX_EXPLOITS_PRIORITY_BONUS: float = 1.0
    VEX_CWES_PRIORITY_BONUS: float = 1.0
    GIT_CLONE_DEPTH: int = 1
    GIT_FSCK_OBJECTS: bool = True

    # Database Configuration
    DB_VEXS_COLLECTION: str = "vexs"
    DB_TIXS_COLLECTION: str = "tixs"
    DB_USERS_COLLECTION: str = "users"
    DB_API_KEY_COLLECTION: str = "api_keys"
    DB_VULNERABILITIES_COLLECTION: str = "vulnerabilities"
    DB_CWES_COLLECTION: str = "cwes"
    DB_EXPLOITS_COLLECTION: str = "exploits"
    MIN_POOL_SIZE: int = 10
    MAX_POOL_SIZE: int = 100
    MAX_IDLE_TIME_MS: int = 60000
    DEFAULT_QUERY_TIMEOUT_MS: int = 5000

    @staticmethod
    def get_os_environment() -> dict[str, str]:
        return dict(environ)

    @staticmethod
    def get_git_config() -> dict[str, str]:
        return {
            "core.hooksPath": "hooks-empty",
            "submodule.recurse": "false",
            "fetch.fsckObjects": "true" if settings.GIT_FSCK_OBJECTS else "false",
            "transfer.fsckObjects": "true" if settings.GIT_FSCK_OBJECTS else "false",
            "core.autocrlf": "false",
            "core.safecrlf": "true",
        }

    @staticmethod
    def get_git_clone_options() -> list[str]:
        return [
            f"--depth={settings.GIT_CLONE_DEPTH}",
            "--single-branch",
            "--no-tags",
            "--filter=blob:none",
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings() # type: ignore[call-arg]


settings: Settings = get_settings()
