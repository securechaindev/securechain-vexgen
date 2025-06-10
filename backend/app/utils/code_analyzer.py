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


async def is_imported(path: str, import_name: str, name: str, manager: str) -> Any:
    match manager:
        case "pypi":
            if ".py" in path:
                return await python_is_imported(path, import_name, name)
        case "npm":
            if ".js" in path or ".ts" in path:
                return await js_ts_is_imported(path, name)
        case "maven":
            if ".java" in path:
                return await java_is_imported(path, name)
        case "cargo":
            if ".rs" in path:
                return await rs_is_imported
        case "nuget":
            if ".cs" in path:
                return await cs_is_imported()

async def get_used_artifacts(path: str, import_name: str, name: str, cve_description: str, affected_artefacts: dict[str, list[str]], manager: str) -> list[dict[str, Any]]:
    match manager:
        case "pypi":
            return await python_get_used_artifacts(path, import_name, name, cve_description, affected_artefacts)
        # TODO: Consider to pass import_name when import names have been extracted for npm, maven, cargo and nuget
        case "npm":
            if "/" in name:
                name = name.split("/")[-1]
            return await js_ts_get_used_artifacts(path, name, cve_description, affected_artefacts)
        case "maven":
            name = name.split(":")[-1]
            return await java_get_used_artifacts(path, name, cve_description, affected_artefacts)
        case "cargo":
            return await rs_get_used_artifacts(path, name, cve_description, affected_artefacts)
        case "nuget":
            return await cs_get_used_artifacts(path, name, cve_description, affected_artefacts)

