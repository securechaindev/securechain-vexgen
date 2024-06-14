from time import sleep
from typing import Any

from requests import ConnectionError, ConnectTimeout, get


async def get_all_cargo_versions(pkg_name: str) -> list[dict[str, Any]]:
    while True:
        try:
            response = get(f"https://crates.io/api/v1/crates/{pkg_name}").json()
            break
        except (ConnectTimeout, ConnectionError):
            sleep(5)
    if "versions" in response:
        versions: list[dict[str, Any]] = []
        for count, version in response["versions"]:
            versions.append(
                {"name": version["num"], "count": count}
            )
        return versions
    return []
