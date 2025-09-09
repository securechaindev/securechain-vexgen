from typing import Any

from app.exceptions import ComponentNotSupportedException

from .codes import (
    cs_get_used_artefacts,
    cs_is_imported,
    java_get_used_artefacts,
    java_is_imported,
    js_ts_get_used_artefacts,
    js_ts_is_imported,
    py_get_used_artefacts,
    py_is_imported,
    rb_get_used_artefacts,
    rb_is_imported,
    rs_get_used_artefacts,
    rs_is_imported,
)


async def is_imported(path: str, import_names: list[str], node_type: str) -> Any:
    match node_type:
        case "PyPIPackage":
            if ".py" in path:
                return await py_is_imported(path, import_names)
        case "NPMPackage":
            if ".js" in path or ".ts" in path:
                return await js_ts_is_imported(path, import_names)
        case "MavenPackage":
            if ".java" in path:
                return await java_is_imported(path, import_names)
        case "CargoPackage":
            if ".rs" in path:
                return await rs_is_imported(path, import_names)
        case "NuGetPackage":
            if ".cs" in path:
                return await cs_is_imported(path, import_names)
        case "RubyGemsPackage":
            if ".rb" in path:
                return await rb_is_imported(path, import_names)
        case _:
            raise ComponentNotSupportedException()


async def get_used_artefacts(path: str, import_names: list[str], cve_description: str, affected_artefacts: dict[str, list[str]], node_type: str) -> list[dict[str, Any]]:
    match node_type:
        case "PyPIPackage":
            return await py_get_used_artefacts(path, import_names, cve_description, affected_artefacts)
        case "NPMPackage":
            return await js_ts_get_used_artefacts(path, import_names, cve_description, affected_artefacts)
        case "MavenPackage":
            return await java_get_used_artefacts(path, import_names, cve_description, affected_artefacts)
        case "CargoPackage":
            return await rs_get_used_artefacts(path, import_names, cve_description, affected_artefacts)
        case "NuGetPackage":
            return await cs_get_used_artefacts(path, import_names, cve_description, affected_artefacts)
        case "RubyGemsPackage":
            return await rb_get_used_artefacts(path, import_names, cve_description, affected_artefacts)
        case _:
            raise ComponentNotSupportedException()
