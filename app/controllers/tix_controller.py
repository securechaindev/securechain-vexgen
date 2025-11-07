from json import dumps
from typing import Annotated
from zipfile import ZipFile

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse

from app.constants import RateLimit, ResponseCode, ResponseMessage
from app.dependencies import get_dual_auth_bearer, get_json_encoder, get_tix_service
from app.exceptions import TixNotFoundException
from app.limiter import limiter
from app.schemas import DownloadTIXRequest, TIXIdPath, UserIdPath
from app.services import TIXService
from app.utils import JSONEncoder

router = APIRouter()

@router.get(
    "/tix/user/{user_id}",
    summary="Retrieve TIX documents for a user",
    description="Fetches all TIX documents associated with a specific user.",
    response_description="List of TIX documents with their metadata and content in JSON format.",
    dependencies=[Depends(get_dual_auth_bearer())],
    tags=["Secure Chain VEXGen - TIX"]
)
@limiter.limit(RateLimit.DEFAULT)
async def get_tixs(
    request: Request,
    path: UserIdPath = Depends(),
    tix_service: TIXService = Depends(get_tix_service),
    json_encoder: JSONEncoder = Depends(get_json_encoder)
) -> JSONResponse:
    tixs = await tix_service.read_user_tixs(path.user_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "data": [tix.model_dump(by_alias=True) for tix in tixs],
                "code": ResponseCode.SUCCESS_TIXS_RETRIEVED,
                "message": ResponseMessage.SUCCESS_TIXS_RETRIEVED
            },
        ),
    )


@router.get(
    "/tix/show/{tix_id}",
    summary="Retrieve a specific TIX document",
    description="Fetches a specific TIX document by its ID.",
    response_description="TIX document metadata and content in JSON format.",
    dependencies=[Depends(get_dual_auth_bearer())],
    tags=["Secure Chain VEXGen - TIX"]
)
@limiter.limit(RateLimit.DEFAULT)
async def get_tix(
    request: Request,
    path: TIXIdPath = Depends(),
    tix_service: TIXService = Depends(get_tix_service),
    json_encoder: JSONEncoder = Depends(get_json_encoder)
) -> JSONResponse:
    tix = await tix_service.read_tix_by_id(path.tix_id)
    if not tix:
        raise TixNotFoundException()
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "data": tix.model_dump(by_alias=True),
                "code": ResponseCode.SUCCESS_TIX_RETRIEVED,
                "message": ResponseMessage.SUCCESS_TIX_RETRIEVED
            }
        ),
    )


@router.post(
    "/tix/download",
    summary="Download TIX",
    description="Fetches the TIX for a specific TIX ID.",
    response_description="ZIP file containing TIX.",
    dependencies=[Depends(get_dual_auth_bearer())],
    tags=["Secure Chain VEXGen - TIX"]
)
@limiter.limit(RateLimit.DOWNLOAD)
async def download_tix(
    request: Request,
    DownloadTIXRequest: Annotated[DownloadTIXRequest, Body()],
    tix_service: TIXService = Depends(get_tix_service)
) -> FileResponse:
    tix = await tix_service.read_tix_by_id(DownloadTIXRequest.tix_id)
    if not tix:
        raise TixNotFoundException()

    tix_dict = tix.model_dump(by_alias=True)
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        myzip.writestr(f"tix_{tix.sbom_name}.json", dumps(tix_dict, indent=2))
    return FileResponse(
        path=zip_path,
        filename="tix.zip",
        headers={'Access-Control-Expose-Headers': 'Content-Disposition'},
        status_code=status.HTTP_200_OK
    )
