from app.database import DatabaseManager


class PackageService:
    def __init__(self, db: DatabaseManager):
        self.driver = db.get_neo4j_driver()

    async def read_package_by_name(self, node_type: str, name: str) -> tuple[str, list[str]]:
        query = f"""
        MATCH(p:{node_type}{{name:$name}})
        RETURN p.name AS package_name,
               coalesce(p.import_names, []) + [p.name] + [coalesce(p.group_id, '')] AS import_names
        """
        async with self.driver.session() as session:
            result = await session.run(
                query,
                name=name
            )
            record = await result.single()
            return (record.get("package_name"), record.get("import_names")) if record else (None, None)
