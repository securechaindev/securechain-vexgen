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
    vexgen_db: AsyncIOMotorDatabase = client.get_database("vexgen_db")
    security_db: AsyncIOMotorDatabase = client.get_database("security_db")
    match collection_name:
        case "users":
            return vexgen_db.get_collection(collection_name)
        case "vexs":
            return vexgen_db.get_collection(collection_name)
        case "vulnerabilities":
            return security_db.get_collection(collection_name)
        case "cwes":
            return security_db.get_collection(collection_name)
        case "exploits":
            return security_db.get_collection(collection_name)
