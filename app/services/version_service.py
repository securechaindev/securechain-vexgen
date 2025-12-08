from app.database import DatabaseManager


class VersionService:
    def __init__(self, db: DatabaseManager):
        self.driver = db.get_neo4j_driver()

    async def read_vulnerability_ids_by_version_and_package(
        self, node_type: str, name: str, version: str
    ) -> list[str]:
        # TODO: Add dynamic labels where Neo4j supports it with indexes
        query = f"""
        MATCH (p:{node_type}{{name:$name}})
        MATCH (p)-[r:HAVE]->(v: Version) WHERE v.name = $version
        RETURN v.vulnerabilities AS vulnerability_ids
        """
        async with self.driver.session() as session:
            result = await session.run(query, name=name, version=version) # type: ignore
            record = await result.single()
        return record.get("vulnerability_ids") if record else []
