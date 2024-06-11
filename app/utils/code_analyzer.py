from typing import Any

from .codes.java_code_analyzer import java_get_used_artifacts, java_is_imported
from .codes.js_ts_code_analyzer import js_ts_get_used_artifacts, js_ts_is_imported
from .codes.python_code_analyzer import python_get_used_artifacts, python_is_imported


async def is_imported(path: str, name: str, package_manager: str) -> Any:
    match package_manager:
        case "pypi":
            if ".py" in path:
                return await python_is_imported(path, name)
        case "npm":
            if ".js" in path or ".ts" in path:
                return await js_ts_is_imported(path, name)
        case "maven":
            if ".java" in path:
                return await java_is_imported(path, name)

async def get_used_artifacts(path: str, name: str, cve_description: str, package_manager: str) -> dict[str, list[int]]:
    match package_manager:
        case "pypi":
            return await python_get_used_artifacts(path, name, cve_description)
        case "npm":
            return await js_ts_get_used_artifacts(path, name, cve_description)
        case "maven":
            return await java_get_used_artifacts(path, name, cve_description)
