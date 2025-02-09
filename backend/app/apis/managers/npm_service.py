from asyncio import TimeoutError, sleep
from typing import Any

from aiohttp import ClientConnectorError, ClientSession


async def get_npm_versions(pkg_name: str) -> list[dict[str, Any]]:
    api_url = f"https://registry.npmjs.org/{pkg_name}"
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
        raw_versions = response["versions"]
        for count, version in enumerate(raw_versions):
            versions.append(
                {
                    "name": version,
                    "count": count,
                    "require_packages": raw_versions[version]["dependencies"]
                    if "dependencies" in raw_versions[version]
                    else {},
                }
            )
        return versions
    return []
