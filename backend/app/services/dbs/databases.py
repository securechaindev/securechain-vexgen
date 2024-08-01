from functools import lru_cache

from app.config import settings
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection
from neo4j import AsyncGraphDatabase, AsyncSession


@lru_cache
def get_graph_db_session(package_manager: str) -> AsyncSession | tuple[AsyncSession]:
    pypi_session: AsyncSession = AsyncGraphDatabase.driver(
        uri=settings.GRAPH_DB_URI_PYPI,
        auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD_PYPI),
    ).session()
    npm_session: AsyncSession = AsyncGraphDatabase.driver(
        uri=settings.GRAPH_DB_URI_NPM,
        auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD_NPM),
    ).session()
    maven_session: AsyncSession = AsyncGraphDatabase.driver(
        uri=settings.GRAPH_DB_URI_MAVEN,
        auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD_MAVEN),
    ).session()
    cargo_session: AsyncSession = AsyncGraphDatabase.driver(
        uri=settings.GRAPH_DB_URI_CARGO,
        auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD_CARGO),
    ).session()
    nuget_session: AsyncSession = AsyncGraphDatabase.driver(
        uri=settings.GRAPH_DB_URI_NUGET,
        auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD_NUGET),
    ).session()
    match package_manager:
        case "pypi":
            return pypi_session
        case "npm":
            return npm_session
        case "maven":
            return maven_session
        case "cargo":
            return cargo_session
        case "nuget":
            return nuget_session
        case "all":
            return pypi_session, npm_session, maven_session


@lru_cache
def get_collection(collection_name: str) -> AsyncIOMotorCollection:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.VULN_DB_URI)
    match collection_name:
        case "env_variables":
            return client.depex.get_collection(collection_name)
        case "cves":
            return client.nvd.get_collection(collection_name)
        case "cpe_matchs":
            return client.nvd.get_collection(collection_name)
        case "cpes":
            return client.nvd.get_collection(collection_name)
        case "cpe_products":
            return client.nvd.get_collection(collection_name)
        case "cwes":
            return client.nvd.get_collection(collection_name)
        case "exploits":
            return client.vulners_db.get_collection(collection_name)
