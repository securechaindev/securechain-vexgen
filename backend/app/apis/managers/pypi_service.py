from asyncio import TimeoutError, sleep
from json import JSONDecodeError
from typing import Any

from aiohttp import ClientConnectorError, ContentTypeError

from app.cache import get_cache, set_cache
from app.http_session import get_session


# TODO: En las nuevas actualizaciones de la API JSON se debería devolver la info de forma diferente, estar atento a nuevas versiones.
async def get_pypi_versions(name: str) -> list[dict[str, Any]]:
    response = await get_cache(name)
    if response:
        versions = response
    else:
        url = f"https://pypi.python.org/pypi/{name}/json"
        session = await get_session()
        while True:
            try:
                async with session.get(url) as resp:
                    response = await resp.json()
                    break
            except (ClientConnectorError, TimeoutError):
                await sleep(5)
            except (JSONDecodeError, ContentTypeError):
                return []
        versions = [{"name": version, "count": count} for count, version in enumerate(response.get("releases", {}))]
        await set_cache(name, versions)
    return versions
