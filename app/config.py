from functools import lru_cache

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


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
