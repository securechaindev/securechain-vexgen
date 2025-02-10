from .dbs import get_graph_db_driver


async def read_cve_ids_by_version_and_package(
    version: str, manager: str, group_id: str, name: str
) -> list[str]:
    query = """
    match (p: Package) where p.manager = $manager and p.group_id = $group_id and p.name = $name
    match (p)-[r:Have]->(v: Version) where v.name = $version
    return v.cves
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, version=version, manager=manager, group_id=group_id, name=name)
        record = await result.single()
    return record[0] if record else []


async def read_versions_names_by_package(
    manager: str, group_id: str, name: str
) -> list[str]:
    query = """
    match (p: Package) where p.manager = $manager and p.group_id = $group_id and p.name = $name
    match (p)-[r:Have]->(v: Version)
    return collect(v.name)
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, manager=manager, group_id=group_id, name=name)
        record = await result.single()
    return record[0] if record else None


async def count_number_of_versions_by_package(
    manager: str, group_id: str, name: str
) -> int:
    query = """
    match (p: Package) where p.manager = $manager and p.group_id = $group_id and p.name = $name
    match (p)-[r:Have]->(v: Version)
    return count(v)
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(query, manager=manager, group_id=group_id, name=name)
        record = await result.single()
    return record[0] if record else None
