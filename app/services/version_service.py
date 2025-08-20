
from .dbs import get_graph_db_driver


async def read_vulnerability_ids_by_version_and_package(
    node_type: str, name: str, version: str
) -> list[str]:
    query = f"""
    MATCH (p:{node_type}{{name:$name}})
    MATCH (p)-[r:HAVE]->(v: Version) WHERE v.name = $version
    RETURN v.vulnerabilities
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, name=name, version=version)
        record = await result.single()
    return record[0] if record else []


async def read_versions_names_by_package(node_type: str, name: str) -> list[str]:
    query = f"""
    MATCH (p:{node_type}{{name:$name}})
    MATCH (p)-[r:HAVE]->(v: Version)
    RETURN collect(v.name)
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, name=name)
        record = await result.single()
    return record[0] if record else None
