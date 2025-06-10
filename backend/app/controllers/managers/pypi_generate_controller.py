from datetime import datetime
from typing import Any

from app.apis import get_pypi_versions
from app.controllers.vulnerability_controller import attribute_vulnerabilities
from app.services import (
    count_number_of_versions_by_package,
    create_package_and_versions,
    create_versions,
    read_versions_names_by_package,
    update_package_moment,
)


async def pypi_create_package(
    name: str,
    constraints: str | None = None,
    parent_id: str | None = None,
    parent_version_name: str | None = None,
) -> None:
    all_versions = await get_pypi_versions(name)
    if all_versions:
        versions = [
            await attribute_vulnerabilities(name, version)
            for version in all_versions
        ]
        await create_package_and_versions(
            {"name": name, "vendor": "n/a", "moment": datetime.now()},
            versions,
            "PyPIPackage",
            constraints,
            parent_id,
            parent_version_name,
        )


async def pypi_search_new_versions(package: dict[str, Any]) -> None:
    all_versions = await get_pypi_versions(package["name"])
    counter = await count_number_of_versions_by_package("PyPIPackage", package["name"])
    if counter < len(all_versions):
        new_versions: list[dict[str, Any]] = []
        actual_versions = await read_versions_names_by_package("PyPIPackage", package["name"])
        for version in all_versions:
            if version.get("name") not in actual_versions:
                version["count"] = counter
                new_version = await attribute_vulnerabilities(package["name"], version)
                new_versions.append(new_version)
                counter += 1
        await create_versions(
            package,
            "PyPIPackage",
            new_versions,
        )
    await update_package_moment("PyPIPackage", package["name"])
