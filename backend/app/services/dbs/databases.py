from functools import lru_cache

from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)
from neo4j import AsyncDriver, AsyncGraphDatabase

from app.config import settings


@lru_cache
def get_graph_db_driver() -> AsyncDriver:
    return AsyncGraphDatabase.driver(
        uri=settings.GRAPH_DB_URI,
        auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD),
    )


@lru_cache
def get_collection(collection_name: str) -> AsyncIOMotorCollection:
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.VULN_DB_URI)
    depex_db: AsyncIOMotorDatabase = client.depex
    nvd_db: AsyncIOMotorDatabase = client.nvd
    vulners_db: AsyncIOMotorDatabase = client.vulners_db
    match collection_name:
        case "users":
            return depex_db.get_collection(collection_name)
        case "vexs":
            return depex_db.get_collection(collection_name)
        case "cves":
            return nvd_db.get_collection(collection_name)
        case "cpe_matchs":
            return nvd_db.get_collection(collection_name)
        case "cpes":
            return nvd_db.get_collection(collection_name)
        case "cpe_products":
            return nvd_db.get_collection(collection_name)
        case "cwes":
            return nvd_db.get_collection(collection_name)
        case "exploits":
            return vulners_db.get_collection(collection_name)
