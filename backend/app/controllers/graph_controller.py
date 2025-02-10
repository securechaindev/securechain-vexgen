from datetime import datetime, timedelta

from fastapi import status
from fastapi.responses import JSONResponse

from app.services import read_package_by_name
from app.utils import json_encoder

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


async def init_pypi_package(name: str) -> JSONResponse:
    """
    Starts graph extraction from a Python Package Index package:

    - **name**: the name of the package as it appears in PyPI
    """
    package = await read_package_by_name("pypi", "none", name)
    if not package:
        await pypi_create_package(name)
    elif package["moment"] < datetime.now() - timedelta(days=10):
        await pypi_search_new_versions(package)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({"message": "Initializing graph"}),
    )


async def init_npm_package(name: str) -> JSONResponse:
    """
    Starts graph extraction from a Node Package Manager package:

    - **name**: the name of the package as it appears in npm
    """
    package = await read_package_by_name("npm", "none", name)
    if not package:
        await npm_create_package(name)
    elif package["moment"] < datetime.now() - timedelta(days=10):
        await npm_search_new_versions(package)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({"message": "initializing"}),
    )


async def init_maven_package(group_id: str, artifact_id: str) -> JSONResponse:
    """
    Starts graph extraction from a Maven Central package:

    - **group_id**: the group_id of the package as it appears in Maven Central
    - **artifact_id**: the artifact_id of the package as it appears in Maven Central
    """
    package = await read_package_by_name("maven", group_id, artifact_id)
    if not package:
        await maven_create_package(group_id, artifact_id)
    elif package["moment"] < datetime.now() - timedelta(days=10):
        await maven_search_new_versions(package)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({"message": "initializing"}),
    )


async def init_cargo_package(name: str) -> JSONResponse:
    """
    Starts graph extraction from a Cargo Crates package:

    - **name**: the name of the package as it appears in Cargo
    """
    package = await read_package_by_name("cargo", "none", name)
    if not package:
        await cargo_create_package(name)
    elif package["moment"] < datetime.now() - timedelta(days=10):
        await cargo_search_new_versions(package)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({"message": "Initializing graph"}),
    )


async def init_nuget_package(name: str) -> JSONResponse:
    """
    Starts graph extraction from a NuGet package:

    - **name**: the name of the package as it appears in NuGet
    """
    package = await read_package_by_name("nuget", "none", name)
    if not package:
        await nuget_create_package(name)
    elif package["moment"] < datetime.now() - timedelta(days=10):
        await nuget_search_new_versions(package)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder({"message": "Initializing graph"}),
    )
