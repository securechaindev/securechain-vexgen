from app.database import DatabaseManager


class VersionService:
    def __init__(self, db: DatabaseManager):
        self._driver = db.get_neo4j_driver()

    async def read_vulnerability_ids_by_version_and_package(
        self, node_type: str, name: str, version: str
    ) -> list[str]:
        query = f"""
        MATCH (p:{node_type}{{name:$name}})
        MATCH (p)-[r:HAVE]->(v: Version) WHERE v.name = $version
        RETURN v.vulnerabilities
        """
        async with self._driver.session() as session:
            result = await session.run(query, name=name, version=version)
            record = await result.single()
        return record[0] if record else []


    async def read_versions_names_by_package(self, node_type: str, name: str) -> list[str]:
        query = f"""
        MATCH (p:{node_type}{{name:$name}})
        MATCH (p)-[r:HAVE]->(v: Version)
        RETURN collect(v.name)
        """
        async with self._driver.session() as session:
            result = await session.run(query, name=name)
            record = await result.single()
        return record[0] if record else None
