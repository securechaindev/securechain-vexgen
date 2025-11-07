from functools import lru_cache
from os import environ

from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env")

    GRAPH_DB_URI: str = ""
    GRAPH_DB_USER: str = ""
    GRAPH_DB_PASSWORD: str = ""
    VULN_DB_URI: str = ""
    VULN_DB_USER: str = ""
    VULN_DB_PASSWORD: str = ""
    DOCS_URL: str | None = None
    SERVICES_ALLOWED_ORIGINS: list[str] = []
    ALGORITHM: str = ""
    JWT_ACCESS_SECRET_KEY: str = ""
    GITHUB_GRAPHQL_API_KEY: str = ""
    VEX_VULNERABILITY_IMPACT_WEIGHT: float = 0.7
    VEX_REACHABLE_CODE_PRIORITY_BONUS: float = 1.0
    VEX_EXPLOITS_PRIORITY_BONUS: float = 1.0
    VEX_CWES_PRIORITY_BONUS: float = 1.0
    GIT_CLONE_DEPTH: int = 1
    GIT_FSCK_OBJECTS: bool = True

    # Database Configuration
    DB_VEXS_COLLECTION: str = "vex"
    DB_TIXS_COLLECTION: str = "tix"
    DB_USERS_COLLECTION: str = "user"
    DB_VULNERABILITIES_COLLECTION: str = "vulnerabilities"
    DB_CWES_COLLECTION: str = "cwes"
    DB_EXPLOITS_COLLECTION: str = "exploits"
    DB_API_KEY_COLLECTION: str = "api_key"
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
    return Settings()


settings: Settings = get_settings()
