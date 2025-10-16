from json import dumps
from shutil import rmtree
from typing import Annotated
from zipfile import ZipFile

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import FileResponse

from app.limiter import limiter
from app.schemas import GenerateVEXTIXRequest
from app.utils import (
    JWTBearer,
    process_sboms,
)

router = APIRouter()
jwt_bearer = JWTBearer()

@router.post(
    "/vex_tix/generate",
    summary="Generate VEX and TIX from a repository",
    description="Generates VEX and TIX for a specific GitHub repository.",
    response_description="ZIP file containing generated VEX and TIX.",
    dependencies=[Depends(jwt_bearer)],
    tags=["Secure Chain VEXGen - VEX/TIX"]
)
@limiter.limit("5/minute")
async def generate_vex_tix(
    request: Request,
    GenerateVEXTIXRequest: Annotated[GenerateVEXTIXRequest, Body()]
) -> FileResponse:
    vexs, tixs, sboms_names, directory = await process_sboms(GenerateVEXTIXRequest)
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        for vex, tix, sbom_name in zip(vexs, tixs, sboms_names, strict=False):
            myzip.writestr(f"vex_{sbom_name}.json", dumps(vex, indent=2))
            myzip.writestr(f"tix_{sbom_name}.json", dumps(tix, indent=2))
    rmtree(directory)
    return FileResponse(path=zip_path, filename="vex_tix_sbom.zip", headers={'Access-Control-Expose-Headers': 'Content-Disposition'}, status_code=status.HTTP_200_OK)
