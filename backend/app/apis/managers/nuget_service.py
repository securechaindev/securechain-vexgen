from asyncio import TimeoutError, sleep
from typing import Any

from aiohttp import ClientConnectorError, ClientSession


async def get_nuget_versions(pkg_name: str) -> list[dict[str, Any]]:
    api_url = f"https://api.nuget.org/v3-flatcontainer/{pkg_name}/index.json"
    async with ClientSession() as session:
        while True:
            try:
                async with session.get(api_url) as response:
                    response = await response.json()
                    break
            except (ClientConnectorError, TimeoutError):
                await sleep(5)
    if "versions" in response:
        versions: list[dict[str, Any]] = []
        for count, version in enumerate(response["versions"]):
            versions.append(
                {"name": version, "count": count}
            )
        return versions
    return []
