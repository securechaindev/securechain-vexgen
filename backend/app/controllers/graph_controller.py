
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter

from app.models.graph import InitPackageRequest
from app.services import read_package_by_name

from .managers import (
    cargo_create_package,
    cargo_search_new_versions,
    maven_create_package,
    maven_search_new_versions,
    npm_create_package,
    npm_search_new_versions,
    nuget_create_package,
    nuget_search_new_versions,
    pypi_create_package,
    pypi_search_new_versions,
)

router = APIRouter()

async def init_package(init_package_request: InitPackageRequest) -> tuple[str, str]:
    name = init_package_request.name.lower()
    package = await read_package_by_name(init_package_request.node_type.value, name)
    if not package:
        await create_package(init_package_request)
    elif package["moment"] < datetime.now() - timedelta(days=10):
        await search_new_versions(package, init_package_request.node_type.value)
    return package["name"], package["import_name"]

async def create_package(init_package_request: InitPackageRequest) -> None:
    match init_package_request.node_type.value:
        case "CargoPackage":
            await cargo_create_package(init_package_request.name)
        case "MavenPackage":
            group_id, artifact_id = init_package_request.name.split(":")
            await maven_create_package(group_id, artifact_id)
        case "NPMPackage":
            await npm_create_package(init_package_request.name)
        case "NuGetPackage":
            await nuget_create_package(init_package_request.name)
        case "PyPIPackage":
            await pypi_create_package(init_package_request.name)


async def search_new_versions(package: dict[str, Any], node_type: str) -> None:
    match node_type:
        case "CargoPackage":
            await cargo_search_new_versions(package)
        case "MavenPackage":
            await maven_search_new_versions(package)
        case "NPMPackage":
            await npm_search_new_versions(package)
        case "NuGetPackage":
            await nuget_search_new_versions(package)
        case "PyPIPackage":
            await pypi_search_new_versions(package)
