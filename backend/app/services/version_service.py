from typing import Any

from .dbs import get_graph_db_driver


async def read_cve_ids_by_version_and_package(
    node_type: str, name: str, version: str
) -> list[str]:
    query = f"""
    MATCH (p:{node_type}{{name:$name}})
    MATCH (p)-[r:Have]->(v: Version) WHERE v.name = $version
    RETURN v.cves
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, name=name, version=version)
        record = await result.single()
    return record[0] if record else []


async def read_versions_names_by_package(node_type: str, name: str) -> list[str]:
    query = f"""
    MATCH (p:{node_type}{{name:$name}})
    MATCH (p)-[r:Have]->(v: Version)
    RETURN collect(v.name)
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, name=name)
        record = await result.single()
    return record[0] if record else None


async def count_number_of_versions_by_package(node_type: str, name: str) -> int:
    query = f"""
    MATCH (p:{node_type}{{name:$name}})
    MATCH (p)-[r:Have]->(v: Version)
    RETURN count(v)
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, name=name)
        record = await result.single()
    return record[0] if record else None


async def create_versions(
    package: dict[str, Any],
    node_type: str,
    versions: list[dict[str, Any]]
) -> dict[str, Any]:
    query = f"""
    MATCH(p:{node_type}{{name:$name}})
    WITH p AS package
    UNWIND $versions AS version
    CREATE(v:Version{{
        name: version.name,
        count: version.count,
        cves: version.cves,
        mean: version.mean,
        weighted_mean: version.weighted_mean
    }})
    CREATE (package)-[rel_v:Have]->(v)
    RETURN collect({{name: v.name, id: elementid(v)}})
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(
            query,
            package,
            versions=versions,
        )
        record = await result.single()
    return record[0] if record else []
