from datetime import datetime
from json import load
from typing import Any

from app.exceptions import InvalidSbomException
from app.templates import create_tix_template, create_vex_template

from .generate_statements import generate_statements
from .get_files_path import get_files_path


async def init_vex_tix(
    owner: str,
    sbom_files: list[str],
    directory: str
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    timestamp = str(datetime.now())
    paths = await get_files_path(directory)
    result = []
    for sbom_file in sbom_files:
        with open(sbom_file, encoding="utf-8") as sbom_file_handle:
            sbom_json = load(sbom_file_handle)
            if "components" in sbom_json and isinstance(sbom_json["components"], list):
                vex = await create_vex_template()
                tix = await create_tix_template()
                tix["author"] = vex["author"] = owner
                tix["timestamp"] = vex["timestamp"] = timestamp
                tix["last_updated"] = vex["last_updated"] = timestamp
                vex, tix = await generate_statements(sbom_json["components"], paths, timestamp, vex, tix)
                result.append((vex, tix))
    if not result:
        raise InvalidSbomException()
    return result
