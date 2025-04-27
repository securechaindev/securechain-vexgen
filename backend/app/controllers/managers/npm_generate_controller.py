from datetime import datetime
from typing import Any

from app.apis import get_npm_versions
from app.controllers.cve_controller import attribute_cves
from app.services import (
    count_number_of_versions_by_package,
    create_package_and_versions,
    create_versions,
    read_cpe_product_by_package_name,
    read_versions_names_by_package,
    update_package_moment,
)


async def npm_create_package(
    name: str,
    constraints: str | None = None,
    parent_id: str | None = None,
    parent_version_name: str | None = None,
) -> None:
    all_versions = await get_npm_versions(name)
    if all_versions:
        cpe_product = await read_cpe_product_by_package_name(name)
        versions = [
            await attribute_cves(version, cpe_product, "npm")
            for version in all_versions
        ]
        await create_package_and_versions(
            {"name": name, "vendor": "n/a", "moment": datetime.now()},
            versions,
            "NPMPackage",
            constraints,
            parent_id,
            parent_version_name,
        )


async def npm_search_new_versions(package: dict[str, Any]) -> None:
    all_versions, all_require_packages = await get_npm_versions(package["name"])
    counter = await count_number_of_versions_by_package("npm", "none", package["name"])
    if counter < len(all_versions):
        no_existing_versions: dict[Any, Any] = {}
        cpe_matches = await read_cpe_product_by_package_name(package["name"])
        actual_versions = await read_versions_names_by_package("NPMPackage", "none", package["name"])
        for version, require_packages in zip(all_versions, all_require_packages):
            if version["release"] not in actual_versions:
                version["count"] = counter
                new_version = await attribute_cves(
                    version, cpe_matches, "npm", package["name"]
                )
                no_existing_versions.update({new_version: require_packages})
                counter += 1
        await create_versions(
            package,
            "NPMPackage",
            no_existing_versions,
        )
    await update_package_moment("NPMPackage", "none", package["name"])
