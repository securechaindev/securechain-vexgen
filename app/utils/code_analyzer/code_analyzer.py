from typing import Any

from .codes import (
    cs_get_used_artifacts,
    cs_is_imported,
    java_get_used_artifacts,
    java_is_imported,
    js_ts_get_used_artifacts,
    js_ts_is_imported,
    python_get_used_artifacts,
    python_is_imported,
    rs_get_used_artifacts,
    rs_is_imported,
)


async def is_imported(path: str, import_name: str, name: str, node_type: str) -> Any:
    match node_type:
        case "PyPIPackage":
            if ".py" in path:
                return await python_is_imported(path, import_name, name)
        case "NPMPackage":
            if ".js" in path or ".ts" in path:
                return await js_ts_is_imported(path, name)
        case "MavenPackage":
            if ".java" in path:
                return await java_is_imported(path, name)
        case "CargoPackage":
            if ".rs" in path:
                return await rs_is_imported
        case "NuGetPackage":
            if ".cs" in path:
                return await cs_is_imported()

async def get_used_artifacts(path: str, import_name: str, name: str, cve_description: str, affected_artefacts: dict[str, list[str]], node_type: str) -> list[dict[str, Any]]:
    match node_type:
        case "PyPIPackage":
            return await python_get_used_artifacts(path, import_name, name, cve_description, affected_artefacts)
        # TODO: Consider to pass import_name when import names have been extracted for npm, maven, cargo and nuget
        case "NPMPackage":
            if "/" in name:
                name = name.split("/")[-1]
            return await js_ts_get_used_artifacts(path, name, cve_description, affected_artefacts)
        case "MavenPackage":
            name = name.split(":")[-1]
            return await java_get_used_artifacts(path, name, cve_description, affected_artefacts)
        case "CargoPackage":
            return await rs_get_used_artifacts(path, name, cve_description, affected_artefacts)
        case "NuGetPackage":
            return await cs_get_used_artifacts(path, name, cve_description, affected_artefacts)

