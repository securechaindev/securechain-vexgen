from json import dumps
from typing import Annotated
from zipfile import ZipFile

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse

from app.limiter import limiter
from app.schemas import DownloadTIXRequest
from app.services import read_tix_by_id, read_user_tixs
from app.utils import JSONEncoder, JWTBearer

router = APIRouter()
json_encoder = JSONEncoder()

@router.get(
    "/tix/user/{user_id}",
    summary="Retrieve TIX documents for a user",
    description="Fetches all TIX documents associated with a specific user.",
    response_description="List of TIX documents with their metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - TIX"]
)
@limiter.limit("25/minute")
async def get_tixs(request: Request,user_id: str) -> JSONResponse:
    tixs = await read_user_tixs(user_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "tixs": tixs,
                "detail": "success_tixs_retrieved"
            },
        ),
    )


@router.get(
    "/tix/show/{tix_id}",
    summary="Retrieve a specific TIX document",
    description="Fetches a specific TIX document by its ID.",
    response_description="TIX document metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - TIX"]
)
@limiter.limit("25/minute")
async def get_tix(request: Request, tix_id: str) -> JSONResponse:
    tix = await read_tix_by_id(tix_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder.encode(
            {
                "tix": tix,
                "detail": "success_tix_retrieved"
            }
        ),
    )


@router.post(
    "/tix/download",
    summary="Download TIX",
    description="Fetches the TIX for a specific TIX ID.",
    response_description="ZIP file containing TIX.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - TIX"]
)
@limiter.limit("25/minute")
async def download_tix(
    request: Request,
    DownloadTIXRequest: Annotated[DownloadTIXRequest, Body()]
) -> FileResponse:
    tix = await read_tix_by_id(DownloadTIXRequest.tix_id)
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        myzip.writestr(f"tix_{tix['sbom_name']}.json", dumps(tix["tix"], indent=2))
    return FileResponse(path=zip_path, filename="tix.zip", headers={'Access-Control-Expose-Headers': 'Content-Disposition'}, status_code=status.HTTP_200_OK)
