from typing import Any

from .managers import (
    get_cargo_versions,
    get_maven_versions,
    get_npm_versions,
    get_nuget_versions,
    get_pypi_versions,
)


async def get_versions(
    manager: str,
    name: str,
    group_id: str | None = None,
) -> list[dict[str, Any]]:
    match manager:
        case "pypi":
            return await get_pypi_versions(name)
        case "npm":
            return await get_npm_versions(name)
        case "maven":
            return await get_maven_versions(group_id, name)
        case "cargo":
            return await get_cargo_versions(name)
        case "nuget":
            return await get_nuget_versions(name)
