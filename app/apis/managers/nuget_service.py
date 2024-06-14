from time import sleep
from typing import Any

from requests import ConnectionError, ConnectTimeout, get


async def get_all_nuget_versions(pkg_name: str) -> list[dict[str, Any]]:
    while True:
        try:
            response = get(f"https://api.nuget.org/v3/registration5-gz-semver2/{pkg_name}/index.json").json()
            break
        except (ConnectTimeout, ConnectionError):
            sleep(5)
    if "items" in response:
        versions: list[dict[str, Any]] = []
        for count, version in response["items"]["items"]:
            versions.append(
                {"name": version["catalogEntry"]["version"], "count": count}
            )
        return versions
    return []