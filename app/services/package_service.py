from .dbs import get_graph_db_driver


async def read_package_by_name(node_type: str, name: str) -> tuple[str, str]:
    query = f"""
    MATCH(p:{node_type}{{name:$name}})
    RETURN p.name, p.import_name
    """
    async with get_graph_db_driver().session() as session:
        result = await session.run(
            query,
            name=name
        )
        record = await result.single()
        return (record[0], record[1]) if record else (None, None)
