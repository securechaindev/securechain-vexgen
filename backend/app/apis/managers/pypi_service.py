from asyncio import TimeoutError, sleep
from json import JSONDecodeError
from typing import Any

from aiohttp import ClientConnectorError, ClientSession


# TODO: En las nuevas actualizaciones de la API JSON se debería devolver la info de forma diferente, estar atento a nuevas versiones.
async def get_pypi_versions(name: str) -> list[dict[str, Any]]:
    api_url = f"https://pypi.python.org/pypi/{name}/json"
    async with ClientSession() as session:
        while True:
            try:
                async with session.get(api_url) as response:
                    response = await response.json()
                    break
            except (ClientConnectorError, TimeoutError):
                await sleep(5)
            except JSONDecodeError:
                return []
    versions: list[dict[str, Any]] = []
    for count, version in enumerate(response.get("releases", [])):
        versions.append(
            {"name": version, "count": count}
        )
    return versions
