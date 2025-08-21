from datetime import datetime
from typing import Any

from pytz import UTC

from app.apis import get_last_commit_date_github
from app.exceptions import SbomNotFoundException
from app.schemas import GenerateVEXTIXRequest
from app.services import (
    create_tix,
    create_vex,
    read_tix_by_owner_name_sbom_name,
    read_vex_by_owner_name_sbom_name,
    update_user_tixs,
    update_user_vexs,
)

from .download_repository import download_repository
from .find_sbom_files import find_sbom_files
from .init_vex_tix import init_vex_tix


async def process_sboms(GenerateVEXTIXRequest: GenerateVEXTIXRequest) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], str]:
    last_commit_date = await get_last_commit_date_github(
        GenerateVEXTIXRequest.owner, GenerateVEXTIXRequest.name
    )
    directory = await download_repository(GenerateVEXTIXRequest.owner, GenerateVEXTIXRequest.name)
    sbom_files = await find_sbom_files(directory)
    if not sbom_files:
        raise SbomNotFoundException()
    sboms_to_process = []
    sboms_names = []
    vexs = []
    tixs = []
    for sbom_file in sbom_files:
        relative_path = sbom_file.replace(directory + "/", "")
        last_vex = await read_vex_by_owner_name_sbom_name(
            GenerateVEXTIXRequest.owner,
            GenerateVEXTIXRequest.name,
            relative_path
        )
        if (
            last_vex
            and last_vex["moment"].replace(tzinfo=UTC)
            >= last_commit_date.replace(tzinfo=UTC)
        ):
            last_tix = await read_tix_by_owner_name_sbom_name(
                GenerateVEXTIXRequest.owner,
                GenerateVEXTIXRequest.name,
                relative_path
            )
            vexs.append(last_vex["vex"])
            tixs.append(last_tix["tix"])
            sboms_names.append(relative_path)
            await update_user_vexs(last_vex["_id"], GenerateVEXTIXRequest.user_id)
        else:
            sboms_to_process.append(sbom_file)
            sboms_names.append(relative_path)
    if sboms_to_process:
        result = await init_vex_tix(GenerateVEXTIXRequest.owner, sboms_to_process, directory)
        for (vex, tix), sbom_name in zip(result, sboms_names):
            vex_id = await create_vex({
                "owner": GenerateVEXTIXRequest.owner,
                "name": GenerateVEXTIXRequest.name,
                "sbom_name": sbom_name,
                "moment": datetime.now(),
                "vex": vex
            })
            tix_id = await create_tix({
                "owner": GenerateVEXTIXRequest.owner,
                "name": GenerateVEXTIXRequest.name,
                "sbom_name": sbom_name,
                "moment": datetime.now(),
                "tix": tix
            })
            await update_user_vexs(vex_id, GenerateVEXTIXRequest.user_id)
            await update_user_tixs(tix_id, GenerateVEXTIXRequest.user_id)
            vexs.append(vex)
            tixs.append(tix)
    return vexs, tixs, sboms_names, directory
