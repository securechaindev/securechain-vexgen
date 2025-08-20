from json import dumps
from shutil import rmtree
from typing import Annotated
from zipfile import ZipFile

from fastapi import APIRouter, Body, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse

from app.limiter import limiter
from app.schemas import DownloadVEXTIXRequest, GenerateVEXTIXRequest
from app.services import (
    read_tix_by_id,
    read_user_tixs,
    read_user_vexs,
    read_vex_by_id,
)
from app.utils import (
    JWTBearer,
    json_encoder,
    process_sboms,
)

router = APIRouter()

@router.get(
    "/vex/user/{user_id}",
    summary="Retrieve VEX documents for a user",
    description="Fetches all VEX documents associated with a specific user.",
    response_description="List of VEX documents with their metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX/TIX"]
)
@limiter.limit("25/minute")
async def get_vexs(request: Request, user_id: str) -> JSONResponse:
    vexs = await read_user_vexs(user_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=await json_encoder(
            {
                "vexs": vexs,
                "detail": "success_vexs_retrieved"
            }
        ),
    )


@router.get(
    "/tix/user/{user_id}",
    summary="Retrieve TIX documents for a user",
    description="Fetches all TIX documents associated with a specific user.",
    response_description="List of TIX documents with their metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX/TIX"]
)
@limiter.limit("25/minute")
async def get_tixs(request: Request,user_id: str) -> JSONResponse:
    tixs = await read_user_tixs(user_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=await json_encoder(
            {
                "tixs": tixs,
                "detail": "success_tixs_retrieved"
            },
        ),
    )


@router.get(
    "/vex/show/{vex_id}",
    summary="Retrieve a specific VEX document",
    description="Fetches a specific VEX document by its ID.",
    response_description="VEX document metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX/TIX"]
)
@limiter.limit("25/minute")
async def get_vex(request: Request, vex_id: str) -> JSONResponse:
    vex = await read_vex_by_id(vex_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=await json_encoder(
            {
                "vex": vex,
                "detail": "success_vex_retrieved"
            }
        ),
    )


@router.get(
    "/tix/show/{tix_id}",
    summary="Retrieve a specific TIX document",
    description="Fetches a specific TIX document by its ID.",
    response_description="TIX document metadata and content in JSON format.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX/TIX"]
)
@limiter.limit("25/minute")
async def get_tix(request: Request, tix_id: str) -> JSONResponse:
    tix = await read_tix_by_id(tix_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=await json_encoder(
            {
                "tix": tix,
                "detail": "success_tix_retrieved"
            }
        ),
    )


@router.get(
    "/vex_tix/download",
    summary="Download VEX and TIX SBOMs",
    description="Fetches the VEX and TIX SBOMs for a specific VEX document.",
    response_description="ZIP file containing VEX and TIX SBOMs.",
    dependencies=[Depends(JWTBearer())],
    tags=["Secure Chain VEXGen - VEX/TIX"]
)
@limiter.limit("25/minute")
async def download_vex_tix(
    request: Request,
    DownloadVEXTIXRequest: Annotated[DownloadVEXTIXRequest, Body()]
) -> FileResponse:
    vex = await read_vex_by_id(DownloadVEXTIXRequest.vex_id)
    tix = await read_tix_by_id(DownloadVEXTIXRequest.tix_id)
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        myzip.writestr(f"vex_{vex['sbom_name']}.json", dumps(vex["vex"], indent=2))
        myzip.writestr(f"tix_{tix['sbom_name']}.json", dumps(tix["tix"], indent=2))
    return FileResponse(path=zip_path, filename="vex.zip", headers={'Access-Control-Expose-Headers': 'Content-Disposition'}, status_code=status.HTTP_200_OK)


@router.post(
    "/vex_tix/generate",
    summary="Generate VEX and TIX from a repository",
    description="Generates VEX and TIX for a specific GitHub repository.",
    response_description="ZIP file containing generated VEX and TIX.",
    dependencies=[Depends(JWTBearer())],
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
        for vex, tix, sbom_name in zip(vexs, tixs, sboms_names):
            myzip.writestr(f"vex_{sbom_name}.json", dumps(vex, indent=2))
            myzip.writestr(f"tix_{sbom_name}.json", dumps(tix, indent=2))
    rmtree(directory)
    return FileResponse(path=zip_path, filename="vex_tix_sbom.zip", headers={'Access-Control-Expose-Headers': 'Content-Disposition'}, status_code=status.HTTP_200_OK)
