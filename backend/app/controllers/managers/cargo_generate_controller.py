from datetime import datetime
from typing import Any

from app.apis import get_cargo_versions
from app.controllers.vulnerability_controller import attribute_vulnerabilities
from app.services import (
    count_number_of_versions_by_package,
    create_package_and_versions,
    create_versions,
    read_versions_names_by_package,
    update_package_moment,
)


async def cargo_create_package(
    name: str,
    constraints: str | None = None,
    parent_id: str | None = None,
    parent_version_name: str | None = None,
) -> None:
    all_versions = await get_cargo_versions(name)
    if all_versions:
        versions = [
            await attribute_vulnerabilities(name, version)
            for version in all_versions
        ]
        await create_package_and_versions(
            {"name": name, "vendor": "n/a", "moment": datetime.now()},
            versions,
            "CargoPackage",
            constraints,
            parent_id,
            parent_version_name,
        )


async def cargo_search_new_versions(package: dict[str, Any]) -> None:
    all_versions = await get_cargo_versions(package["name"])
    counter = await count_number_of_versions_by_package("CargoPackage", package["name"])
    if counter < len(all_versions):
        new_versions: list[dict[str, Any]] = []
        actual_versions = await read_versions_names_by_package("CargoPackage", package["name"])
        for version in all_versions:
            if version.get("name") not in actual_versions:
                version["count"] = counter
                new_version = await attribute_vulnerabilities(package["name"], version)
                new_versions.append(new_version)
                counter += 1
        await create_versions(
            package,
            "CargoPackage",
            new_versions,
        )
    await update_package_moment("CargoPackage", package["name"])
