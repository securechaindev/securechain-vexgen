from typing import Any

from .managers import (
    get_cargo_versions,
    get_maven_versions,
    get_npm_versions,
    get_nuget_versions,
    get_pypi_versions,
)


async def get_all_versions(
    manager: str,
    package_name: str | None = None,
    package_artifact_id: str | None = None,
    package_group_id: str | None = None,
) -> list[dict[str, Any]]:
    match manager:
        case "pypi":
            return await get_pypi_versions(package_name)
        case "npm":
            return await get_npm_versions(package_name)
        case "maven":
            return await get_maven_versions(package_artifact_id, package_group_id)
        case "cargo":
            return await get_cargo_versions(package_name)
        case "nuget":
            return await get_nuget_versions(package_name)
