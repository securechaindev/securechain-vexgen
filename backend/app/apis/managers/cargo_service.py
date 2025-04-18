from asyncio import TimeoutError, sleep
from json import JSONDecodeError
from typing import Any

from aiohttp import ClientConnectorError, ContentTypeError

from app.cache import get_cache, set_cache
from app.http_session import get_session


async def get_cargo_versions(name: str) -> list[dict[str, Any]]:
    response = await get_cache(name)
    if response:
        versions = response
    else:
        url = f"https://crates.io/api/v1/crates/{name}"
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
        versions = [{"name": version.get("num"), "count": count} for count, version in enumerate(response.get("versions", []))]
        await set_cache(name, versions)
    return versions
