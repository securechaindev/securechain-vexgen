from typing import Any

from app.database import DatabaseManager


class PackageService:
    def __init__(self, db: DatabaseManager):
        self.driver = db.get_neo4j_driver()

    async def read_package_by_name(self, node_type: str, name: str) -> dict[str, Any] | None:
        query = f"""
        MATCH(p:{node_type}{{name:$name}})
        RETURN {{name: p.name,
            import_names: coalesce(p.import_names, []) + [p.name] + [coalesce(p.group_id, '')]}} as package
        """
        async with self.driver.session() as session:
            result = await session.run(query, name=name)
            record = await result.single()
            return record.get("package") if record else None
