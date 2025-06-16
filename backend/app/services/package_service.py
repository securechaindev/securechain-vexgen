from datetime import datetime
from typing import Any

from .dbs import get_graph_db_driver


async def create_package_and_versions(
    package: dict[str, Any],
    versions: list[dict[str, Any]],
    node_type: str,
    constraints: str | None = None,
    parent_id: str | None = None,
    parent_version_name: str | None = None,
) -> None:
    query_part1 = ""
    query_part3 = ""
    if parent_id:
        query_part1 = (
            """
            MATCH (parent:RequirementFile|Version)
            WHERE elementid(parent) = $parent_id
            """
        )
        query_part3 = (
            f"CREATE (parent)-[rel_p:Requires{{constraints:$constraints{", parent_version_name:$parent_version_name" if parent_version_name else ""}}}]->(p)"
        )
    query = f"""
    {query_part1}
    MERGE(p:{node_type}{{{"group_id:$group_id, artifact_id:$artifact_id," if node_type == "MavenPackage" else ""}name:$name}})
    ON CREATE SET p.vendor = $vendor, p.moment = $moment
    ON MATCH SET p.vendor = $vendor, p.moment = $moment
    {query_part3}
    WITH p AS package
    UNWIND $versions AS version
    CREATE(v:Version{{
        name: version.name,
        count: version.count,
        vulnerabilities: version.vulnerabilities,
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
            constraints=constraints,
            parent_id=parent_id,
            parent_version_name=parent_version_name,
            versions=versions,
        )
        await result.single()


async def read_package_by_name(node_type: str, name: str) -> dict[str, Any]:
    query = f"""
    MATCH(p:{node_type}{{name:$name}})
    RETURN p{{id: elementid(p), .*}}
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(
            query,
            name=name
        )
        record = await result.single()
    return record[0] if record else None


async def update_package_moment(node_type: str, name: str) -> None:
    query = f"""
    MATCH(p:{node_type}{{name:$name}})
    SET p.moment = $moment
    """
    async with get_graph_db_driver().session() as session:
        await session.run(query, name=name, moment=datetime.now())
