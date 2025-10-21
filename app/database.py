from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)
from neo4j import AsyncDriver, AsyncGraphDatabase

from app.config import settings
from app.constants import DatabaseConfig
from app.logger import logger


class DatabaseManager:
    _instance: "DatabaseManager | None" = None
    _mongo_client: AsyncIOMotorClient | None = None
    _neo4j_driver: AsyncDriver | None = None
    _securechain_db: AsyncIOMotorDatabase | None = None
    _vulnerabilities_db: AsyncIOMotorDatabase | None = None

    def __new__(cls) -> "DatabaseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self) -> None:
        if self._mongo_client is None:
            logger.info("Initializing MongoDB connection pool...")
            self._mongo_client = AsyncIOMotorClient(
                settings.VULN_DB_URI,
                minPoolSize=DatabaseConfig.MIN_POOL_SIZE,
                maxPoolSize=DatabaseConfig.MAX_POOL_SIZE,
                maxIdleTimeMS=DatabaseConfig.MAX_IDLE_TIME_MS,
                serverSelectionTimeoutMS=DatabaseConfig.DEFAULT_QUERY_TIMEOUT_MS,
            )
            self._securechain_db = self._mongo_client.get_database("securechain")
            self._vulnerabilities_db = self._mongo_client.get_database("vulnerabilities")
            logger.info("MongoDB connection pool initialized")

        if self._neo4j_driver is None:
            logger.info("Initializing Neo4j driver...")
            self._neo4j_driver = AsyncGraphDatabase.driver(
                uri=settings.GRAPH_DB_URI,
                auth=(settings.GRAPH_DB_USER, settings.GRAPH_DB_PASSWORD),
                max_connection_pool_size=DatabaseConfig.MAX_POOL_SIZE,
            )
            logger.info("Neo4j driver initialized")

    async def close(self) -> None:
        if self._mongo_client:
            logger.info("Closing MongoDB connection...")
            self._mongo_client.close()
            self._mongo_client = None
            self._securechain_db = None
            self._vulnerabilities_db = None
            logger.info("MongoDB connection closed")

        if self._neo4j_driver:
            logger.info("Closing Neo4j driver...")
            await self._neo4j_driver.close()
            self._neo4j_driver = None
            logger.info("Neo4j driver closed")

    def get_user_collection(self) -> AsyncIOMotorCollection:
        if self._securechain_db is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._securechain_db.get_collection(DatabaseConfig.USERS_COLLECTION)

    def get_vexs_collection(self) -> AsyncIOMotorCollection:
        if self._securechain_db is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._securechain_db.get_collection(DatabaseConfig.VEXS_COLLECTION)

    def get_tixs_collection(self) -> AsyncIOMotorCollection:
        if self._securechain_db is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._securechain_db.get_collection(DatabaseConfig.TIXS_COLLECTION)

    def get_vulnerabilities_collection(self) -> AsyncIOMotorCollection:
        if self._vulnerabilities_db is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._vulnerabilities_db.get_collection("vulnerabilities")

    def get_cwes_collection(self) -> AsyncIOMotorCollection:
        if self._vulnerabilities_db is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._vulnerabilities_db.get_collection("cwes")

    def get_exploits_collection(self) -> AsyncIOMotorCollection:
        if self._vulnerabilities_db is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._vulnerabilities_db.get_collection("exploits")

    def get_neo4j_driver(self) -> AsyncDriver:
        if self._neo4j_driver is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self._neo4j_driver

_db_manager: DatabaseManager | None = None

def get_database_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
