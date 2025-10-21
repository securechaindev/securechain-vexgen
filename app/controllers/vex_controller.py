from json import dumps
from typing import Annotated
from zipfile import ZipFile

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse

from app.constants import RateLimit
from app.dependencies import get_json_encoder, get_jwt_bearer, get_vex_service
from app.limiter import limiter
from app.schemas import DownloadVEXRequest, HTTPStatusMessage, UserIdPath, VEXIdPath
from app.services import VEXService
from app.utils import JSONEncoder

router = APIRouter()

@router.get(
    "/vex/user/{user_id}",
    summary="Retrieve VEX documents for a user",
    description="Fetches all VEX documents associated with a specific user.",
    response_description="List of VEX documents with their metadata and content in JSON format.",
    dependencies=[Depends(get_jwt_bearer)],
    tags=["Secure Chain VEXGen - VEX"]
)
@limiter.limit(RateLimit.DEFAULT)
async def get_vexs(
    request: Request,
    path: UserIdPath = Depends(),
    vex_service: VEXService = Depends(get_vex_service),
    json_encoder: JSONEncoder = Depends(get_json_encoder)
) -> JSONResponse:
    vexs = await vex_service.read_user_vexs(path.user_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "vexs": [vex.model_dump(by_alias=True) for vex in vexs],
                "detail": HTTPStatusMessage.SUCCESS_VEXS_RETRIEVED
            }
        ),
    )


@router.get(
    "/vex/show/{vex_id}",
    summary="Retrieve a specific VEX document",
    description="Fetches a specific VEX document by its ID.",
    response_description="VEX document metadata and content in JSON format.",
    dependencies=[Depends(get_jwt_bearer)],
    tags=["Secure Chain VEXGen - VEX"]
)
@limiter.limit(RateLimit.DEFAULT)
async def get_vex(
    request: Request,
    path: VEXIdPath = Depends(),
    vex_service: VEXService = Depends(get_vex_service),
    json_encoder: JSONEncoder = Depends(get_json_encoder)
) -> JSONResponse:
    vex = await vex_service.read_vex_by_id(path.vex_id)
    if not vex:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": HTTPStatusMessage.ERROR_VEX_NOT_FOUND}
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "vex": vex.model_dump(by_alias=True),
                "detail": HTTPStatusMessage.SUCCESS_VEX_RETRIEVED
            }
        ),
    )

@router.post(
    "/vex/download",
    summary="Download VEX",
    description="Fetches the VEX for a specific VEX ID.",
    response_description="ZIP file containing VEX.",
    dependencies=[Depends(get_jwt_bearer)],
    tags=["Secure Chain VEXGen - VEX"]
)
@limiter.limit(RateLimit.DOWNLOAD)
async def download_vex(
    request: Request,
    DownloadVEXRequest: Annotated[DownloadVEXRequest, Body()],
    vex_service: VEXService = Depends(get_vex_service)
) -> FileResponse:
    vex = await vex_service.read_vex_by_id(DownloadVEXRequest.vex_id)
    if not vex:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": HTTPStatusMessage.ERROR_VEX_NOT_FOUND}
        )

    vex_dict = vex.model_dump(by_alias=True)
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        myzip.writestr(f"vex_{vex.sbom_name}.json", dumps(vex_dict, indent=2))
    return FileResponse(
        path=zip_path,
        filename="vex.zip",
        headers={'Access-Control-Expose-Headers': 'Content-Disposition'},
        status_code=status.HTTP_200_OK
    )
