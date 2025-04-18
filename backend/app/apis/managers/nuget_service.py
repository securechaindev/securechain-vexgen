from asyncio import TimeoutError, sleep
from json import JSONDecodeError
from typing import Any

from aiohttp import ClientConnectorError, ContentTypeError

from app.cache import get_cache, set_cache
from app.http_session import get_session


async def fetch_page_versions(url: str) -> list[dict[str, Any]]:
    session = await get_session()
    while True:
        response = await get_cache(url)
        if not response:
            try:
                async with session.get(url) as resp:
                    response = await resp.json()
                    await set_cache(url, response)
                    return response.get("items", [])
            except (ClientConnectorError, TimeoutError):
                await sleep(5)
            except (JSONDecodeError, ContentTypeError):
                return []

async def get_nuget_versions(
    name: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    response = await get_cache(name)
    if response:
        versions = response
    else:
        url = f"https://api.nuget.org/v3/registration5-gz-semver2/{name}/index.json"
        session = await get_session()
        while True:
            try:
                async with session.get(url) as resp:
                    response = await resp.json()
                    break
            except (ClientConnectorError, TimeoutError):
                await sleep(5)
            except (JSONDecodeError, ContentTypeError):
                return [], []
        versions = []
        count = 0
        for item in response.get("items", []) or []:
            if "items" in item:
                for version_item in item.get("items", []):
                    catalog_entry = version_item.get("catalogEntry", {})
                    versions.append({"name": catalog_entry.get("version"), "count": count})
                    count += 1
            elif "@id" in item:
                for version_item in await fetch_page_versions(item.get("@id")):
                    catalog_entry = version_item.get("catalogEntry", {})
                    versions.append({"name": catalog_entry.get("version"), "count": count})
                    count += 1
        await set_cache(name, versions)
    return versions
