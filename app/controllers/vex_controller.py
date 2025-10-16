from json import dumps
from typing import Annotated
from zipfile import ZipFile

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse

from app.limiter import limiter
from app.schemas import DownloadVEXRequest
from app.services import read_user_vexs, read_vex_by_id
from app.utils import JWTBearer, JSONEncoder

router = APIRouter()
json_encoder = JSONEncoder()

@router.get(
    "/vex/user/{user_id}",
    summary="Retrieve VEX documents for a user",
    description="Fetches all VEX documents associated with a specific user.",
    response_description="List of VEX documents with their metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX"]
)
@limiter.limit("25/minute")
async def get_vexs(request: Request, user_id: str) -> JSONResponse:
    vexs = await read_user_vexs(user_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "vexs": vexs,
                "detail": "success_vexs_retrieved"
            }
        ),
    )


@router.get(
    "/vex/show/{vex_id}",
    summary="Retrieve a specific VEX document",
    description="Fetches a specific VEX document by its ID.",
    response_description="VEX document metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX"]
)
@limiter.limit("25/minute")
async def get_vex(request: Request, vex_id: str) -> JSONResponse:
    vex = await read_vex_by_id(vex_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "vex": vex,
                "detail": "success_vex_retrieved"
            }
        ),
    )

@router.post(
    "/vex/download",
    summary="Download VEX",
    description="Fetches the VEX for a specific VEX ID.",
    response_description="ZIP file containing VEX.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX"]
)
@limiter.limit("25/minute")
async def download_vex(
    request: Request,
    DownloadVEXRequest: Annotated[DownloadVEXRequest, Body()]
) -> FileResponse:
    vex = await read_vex_by_id(DownloadVEXRequest.vex_id)
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        myzip.writestr(f"vex_{vex['sbom_name']}.json", dumps(vex["vex"], indent=2))
    return FileResponse(path=zip_path, filename="vex.zip", headers={'Access-Control-Expose-Headers': 'Content-Disposition'}, status_code=status.HTTP_200_OK)
