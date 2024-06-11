from time import sleep
from typing import Any

from requests import ConnectionError, ConnectTimeout, get


async def get_all_npm_versions(pkg_name: str) -> list[dict[str, Any]]:
    while True:
        try:
            response = get(f"https://registry.npmjs.org/{pkg_name}").json()
            break
        except (ConnectTimeout, ConnectionError):
            sleep(5)
    if "versions" in response:
        versions = []
        raw_versions = response["versions"]
        for count, version in enumerate(raw_versions):
            versions.append(
                {
                    "name": version,
                    "release_date": None,
                    "count": count,
                    "require_packages": raw_versions[version]["dependencies"]
                    if "dependencies" in raw_versions[version]
                    else {},
                }
            )
        return versions
    return []
