from datetime import datetime
from typing import Any

from .dbs import get_graph_db_driver


async def create_package_and_versions(
    package: dict[str, Any],
    versions: list[dict[str, Any]],
    constraints: str | None = None,
    parent_id: str | None = None,
    parent_version_name: str | None = None,
) -> None:
    query_part1 = (
        """
        match (parent:RequirementFile|Version)
        where elementid(parent) = $parent_id
        """
        if parent_id
        else ""
    )
    query_part3 = (
        f"create (parent)-[rel_p:Requires{{constraints:$constraints{", parent_version_name:$parent_version_name" if parent_version_name else ""}}}]->(p)"
        if parent_id
        else ""
    )
    query = f"""
    {query_part1}
    create(p:Package{{manager:$manager, group_id:$group_id, name:$name, moment:$moment}})
    {query_part3}
    with p as package
    unwind $versions as version
    create(v:Version{{
        name: version.name,
        release_date: version.release_date,
        count: version.count,
        cves: version.cves,
        mean: version.mean,
        weighted_mean: version.weighted_mean
    }})
    create (package)-[rel_v:Have]->(v)
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


async def read_package_by_name(manager: str, group_id: str, name: str) -> dict[str, Any]:
    query = """
    match (p:Package)
    where p.manager = $manager and p.group_id = $group_id and p.name = $name
    return p{id: elementid(p), .*}
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(
            query,
            manager = manager,
            group_id=group_id,
            name=name
        )
        record = await result.single()
    return record[0] if record else None


async def update_package_moment(manager: str, group_id: str, name: str) -> None:
    query = """
    match (p:Package) where p.manager = $manager and p.group_id = $group_id and p.name = $name
    set p.moment = $moment
    """
    async with get_graph_db_driver().session() as session:
        await session.run(query, manager=manager, group_id=group_id, name=name, moment=datetime.now())
