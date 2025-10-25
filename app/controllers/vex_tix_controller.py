from json import dumps
from os import replace as atomic_rename
from shutil import rmtree
from tempfile import NamedTemporaryFile
from typing import Annotated
from zipfile import ZipFile

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import FileResponse

from app.apis import GitHubService
from app.constants import RateLimit
from app.dependencies import (
    get_jwt_bearer,
    get_tix_service,
    get_vex_service,
    get_github_service,
)
from app.domain import SBOMProcessor
from app.limiter import limiter
from app.schemas import GenerateVEXTIXRequest
from app.services import TIXService, VEXService

router = APIRouter()

@router.post(
    "/vex_tix/generate",
    summary="Generate VEX and TIX from a repository",
    description="Generates VEX and TIX for a specific GitHub repository.",
    response_description="ZIP file containing generated VEX and TIX.",
    dependencies=[Depends(get_jwt_bearer)],
    tags=["Secure Chain VEXGen - VEX/TIX"]
)
@limiter.limit(RateLimit.DOWNLOAD)
async def generate_vex_tix(
    request: Request,
    generate_vex_tix_request: Annotated[GenerateVEXTIXRequest, Body()],
    vex_service: VEXService = Depends(get_vex_service),
    tix_service: TIXService = Depends(get_tix_service),
    github_service: GitHubService = Depends(get_github_service)
) -> FileResponse:
    sbom_processor = SBOMProcessor(
        generate_vex_tix_request,
        github_service,
        vex_service,
        tix_service
    )
    result = await sbom_processor.process_sboms()

    final_zip_path = "vex_tix_sbom.zip"

    with NamedTemporaryFile(mode='wb', delete=False, suffix='.zip') as temp_file:
        temp_zip_path = temp_file.name

    try:
        with ZipFile(temp_zip_path, "w") as myzip:
            for vex, tix, sbom_path in zip(result.vex_list, result.tix_list, result.sbom_paths, strict=False):
                myzip.writestr(f"vex_{sbom_path}.json", dumps(vex, indent=2))
                myzip.writestr(f"tix_{sbom_path}.json", dumps(tix, indent=2))

        atomic_rename(temp_zip_path, final_zip_path)
    except Exception:
        if temp_zip_path:
            rmtree(temp_zip_path, ignore_errors=True)
        raise
    finally:
        rmtree(result.directory, ignore_errors=True)

    return FileResponse(
        path=final_zip_path,
        filename="vex_tix_sbom.zip",
        headers={'Access-Control-Expose-Headers': 'Content-Disposition'},
        status_code=status.HTTP_200_OK
    )
