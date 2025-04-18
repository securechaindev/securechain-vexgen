from asyncio import TimeoutError, sleep
from typing import Any

from aiohttp import ClientConnectorError, ContentTypeError

from app.cache import get_cache, set_cache
from app.http_session import get_session


async def get_maven_versions(
    group_id: str,
    artifact_id: str,
) -> list[dict[str, Any]]:
    key = f"{group_id}:{artifact_id}"
    response = await get_cache(key)
    if response:
        versions = response
    else:
        versions: list[dict[str, Any]] = []
        session = await get_session()
        start = 0
        while True:
            url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&core=gav&rows=200&start={start}"
            while True:
                try:
                    async with session.get(url) as response:
                        response = await response.json()
                        await set_cache(url, response)
                        break
                except (ClientConnectorError, TimeoutError):
                    await sleep(5)
                except ContentTypeError:
                    return versions
            start += 200
            if not response.get("response").get("docs", []):
                break
            for count, version in enumerate(response.get("response", {}).get("docs", [])):
                versions.append({"name": version.get("v"), "count": count})
        await set_cache(key, versions)
    return versions
