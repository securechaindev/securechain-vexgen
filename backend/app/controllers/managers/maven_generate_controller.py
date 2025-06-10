from datetime import datetime
from typing import Any

from app.apis import get_maven_versions
from app.controllers.vulnerability_controller import attribute_vulnerabilities
from app.services import (
    count_number_of_versions_by_package,
    create_package_and_versions,
    create_versions,
    read_versions_names_by_package,
    update_package_moment,
)


async def maven_create_package(
    group_id: str,
    artifact_id: str,
    constraints: str | None = None,
    parent_id: str | None = None,
    parent_version_name: str | None = None,
) -> None:
    all_versions = await get_maven_versions(group_id, artifact_id)
    if all_versions:
        versions = [
            await attribute_vulnerabilities(f"{group_id}:{artifact_id}", version)
            for version in all_versions
        ]
        await create_package_and_versions(
            {"group_id": group_id, "artifact_id": artifact_id, "name": f"{group_id}:{artifact_id}", "vendor": "n/a", "moment": datetime.now()},
            versions,
            "MavenPackage",
            constraints,
            parent_id,
            parent_version_name,
        )


async def maven_search_new_versions(package: dict[str, Any]) -> None:
    all_versions = await get_maven_versions(package["group_id"], package["artifact_id"])
    counter = await count_number_of_versions_by_package("MavenPackage", package["name"])
    if counter < len(all_versions):
        new_versions: list[dict[str, Any]] = []
        actual_versions = await read_versions_names_by_package("MavenPackage", package["name"])
        for version in all_versions:
            if version.get("name") not in actual_versions:
                version["count"] = counter
                new_version = await attribute_vulnerabilities(package["name"], version)
                new_versions.append(new_version)
                counter += 1
        await create_versions(
            package,
            "MavenPackage",
            new_versions,
        )
    await update_package_moment("MavenPackage", package["name"])
