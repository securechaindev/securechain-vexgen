from datetime import datetime
from typing import Any

from .dbs.databases import get_graph_db_session


async def create_repository(repository: dict[str, Any], package_manager: str) -> str:
    query = """
    merge(r: Repository{
        owner: $owner,
        name: $name,
        moment: $moment,
        add_extras: $add_extras,
        is_complete: $is_complete
    })
    return elementid(r) as id
    """
    session = get_graph_db_session(package_manager)
    result = await session.run(query, repository)
    record = await result.single()
    return record[0]


async def read_repositories_moment(owner: str, name: str) -> dict[str, datetime | bool]:
    query = """
    match(r: Repository{owner: $owner, name: $name}) return {moment: r.moment, is_complete: r.is_complete}
    """
    session = get_graph_db_session("PIP")
    result = await session.run(query, owner=owner, name=name)
    record = await result.single()
    for session in get_graph_db_session("ALL"):
        result = await session.run(query, owner=owner, name=name)
        record = await result.single()
        if record:
            break
    return record[0] if record else {"moment": None, "is_complete": True}


async def read_repositories(owner: str, name: str) -> dict[str, str]:
    repository_ids: dict[str, str] = {}
    query = """
    match(r: Repository{owner: $owner, name: $name}) return elementid(r)
    """
    pip_session, npm_session, mvn_session = get_graph_db_session("ALL")
    pip_result = await pip_session.run(query, owner=owner, name=name)
    pip_record = await pip_result.single()
    repository_ids.update({"PIP": pip_record[0] if pip_record else None})
    npm_result = await npm_session.run(query, owner=owner, name=name)
    npm_record = await npm_result.single()
    repository_ids.update({"NPM": npm_record[0] if npm_record else None})
    mvn_result = await mvn_session.run(query, owner=owner, name=name)
    mvn_record = await mvn_result.single()
    repository_ids.update({"MVN": mvn_record[0] if mvn_record else None})
    return repository_ids


async def read_repository_by_id(
    repository_id: str, package_manager: str
) -> dict[str, str]:
    query = """
    match(r: Repository) where elementid(r)=$repository_id return {name: r.name, owner: r.owner}
    """
    session = get_graph_db_session(package_manager)
    result = await session.run(query, repository_id=repository_id)
    record = await result.single()
    return record[0] if record else None


async def update_repository_is_complete(
    repository_id: str, is_complete: bool, package_manager: str
) -> None:
    query = """
    match (r: Repository) where elementid(r) = $repository_id
    set r.is_complete = $is_complete
    """
    session = get_graph_db_session(package_manager)
    await session.run(query, repository_id=repository_id, is_complete=is_complete)


async def update_repository_moment(repository_id: str, package_manager: str) -> None:
    query = """
    match (r: Repository) where elementid(r) = $repository_id
    set r.moment = $moment
    """
    session = get_graph_db_session(package_manager)
    await session.run(query, repository_id=repository_id, moment=datetime.now())
