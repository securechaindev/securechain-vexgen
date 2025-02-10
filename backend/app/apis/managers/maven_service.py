from asyncio import TimeoutError, sleep
from typing import Any

from aiohttp import ClientConnectorError, ClientSession


async def get_maven_versions(
    group_id: str, artifact_id: str
) -> list[dict[str, Any]]:
    versions: list[dict[str, Any]] = []
    start = 0
    docs = True
    while docs:
        api_url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&core=gav&rows=200&start={start}"
        async with ClientSession() as session:
            while True:
                try:
                    async with session.get(api_url) as response:
                        response = await response.json()
                        break
                except (ClientConnectorError, TimeoutError):
                    await sleep(5)
        start += 200
        docs = response.get("response").get("docs", [])
        for count, version in enumerate(response.get("response").get("docs", [])):
            versions.append({"name": version.get("v"), "count": count})
    return versions
