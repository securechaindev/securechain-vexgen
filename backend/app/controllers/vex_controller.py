import os
from datetime import datetime
from glob import glob
from json import dumps, load
from os.path import exists, isdir
from shutil import rmtree
from typing import Annotated, Any
from zipfile import ZipFile

from fastapi import APIRouter, Body, status
from fastapi.responses import FileResponse, JSONResponse
from pytz import UTC

from app.apis import get_last_commit_date_github
from app.controllers import init_package
from app.exceptions import (
    InvalidMavenComponentException,
    InvalidRepositoryException,
    InvalidSbomException,
    SbomNotFoundException,
)
from app.models.graph import InitPackageRequest, NodeType
from app.models.vex import GenerateVEXRequest
from app.services import (
    create_vex,
    read_user_vexs,
    read_vex_by_id,
    read_vex_moment_by_owner_name_sbom_path,
    read_vulnerability_by_id,
    read_vulnerability_ids_by_version_and_package,
    update_user_vexs,
)
from app.utils import (
    download_repository,
    get_node_type,
    get_used_artifacts,
    is_imported,
    json_encoder,
    load_json_template,
)

router = APIRouter()

@router.get("/api/vex/user/{user_id}")
async def get_vexs(user_id: str) -> JSONResponse:
    vexs = await read_user_vexs(user_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder(vexs),
    )


@router.get("/api/vex/show/{vex_id}")
async def get_vex(vex_id: str) -> JSONResponse:
    vex = await read_vex_by_id(vex_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=json_encoder(vex),
    )


@router.get("/api/vex/download/{vex_id}")
async def download_vex(vex_id: str) -> FileResponse:
    vex = await read_vex_by_id(vex_id)
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        myzip.writestr(f"vex_{vex['sbom_name']}.json", dumps(vex["vex"], indent=2))
        myzip.writestr(f"tix_{vex['sbom_name']}.json", dumps(vex["tix"], indent=2))
    return FileResponse(path=zip_path, filename="vex.zip", headers={'Access-Control-Expose-Headers': 'Content-Disposition'}, status_code=status.HTTP_200_OK)


@router.post("/api/vex/generate")
async def generate_vex_tix(
    GenerateVEXRequest: Annotated[GenerateVEXRequest, Body()]
) -> FileResponse:
    last_commit_date = await get_last_commit_date_github(
        GenerateVEXRequest.owner, GenerateVEXRequest.name
    )
    if not last_commit_date:
        raise InvalidRepositoryException()
    carpeta_descarga = await download_repository(GenerateVEXRequest.owner, GenerateVEXRequest.name)
    sbom_files = await find_sbom_files(carpeta_descarga)
    if not sbom_files:
        raise SbomNotFoundException()
    sboms_to_process = []
    sboms_to_process_names = []
    cached_results = []
    for sbom_file in sbom_files:
        relative_path = sbom_file.replace(carpeta_descarga + "/", "")
        last_vex = await read_vex_moment_by_owner_name_sbom_path(
            GenerateVEXRequest.owner,
            GenerateVEXRequest.name,
            relative_path
        )
        if (
            last_vex
            and last_vex["moment"].replace(tzinfo=UTC)
            >= last_commit_date.replace(tzinfo=UTC)
        ):
            cached_results.append((last_vex["vex"], last_vex["tix"]))
            await update_user_vexs(last_vex["_id"], GenerateVEXRequest.user_id)
        else:
            sboms_to_process.append(sbom_file)
            sboms_to_process_names.append(relative_path)
    if sboms_to_process:
        paths = await get_files_path(carpeta_descarga)
        result = await init_vex_tix(GenerateVEXRequest.owner, sboms_to_process, paths)
        for (vex, tix), sbom_name in zip(result, sboms_to_process_names):
            vex_id = await create_vex({
                "owner": GenerateVEXRequest.owner,
                "name": GenerateVEXRequest.name,
                "sbom_name": sbom_name,
                "moment": datetime.now(),
                "vex": vex,
                "tix": tix
            })
            await update_user_vexs(vex_id, GenerateVEXRequest.user_id)
            cached_results.append((vex, tix))
    zip_path = "vex_tix_sbom.zip"
    with ZipFile(zip_path, "w") as myzip:
        for (vex, tix), sbom_name in zip(cached_results, sboms_to_process_names):
            myzip.writestr(f"vex_{sbom_name}.json", dumps(vex, indent=2))
            myzip.writestr(f"tix_{sbom_name}.json", dumps(tix, indent=2))
    rmtree(carpeta_descarga)
    return FileResponse(path=zip_path, filename="vex_tix_sbom.zip", headers={'Access-Control-Expose-Headers': 'Content-Disposition'}, status_code=status.HTTP_200_OK)


async def find_sbom_files(directory: str) -> list[str]:
    sbom_files = []
    for branch in ("main", "master"):
        if exists(f"{directory}/{branch}"):
            for root, _, files in os.walk(f"{directory}/{branch}"):
                for file in files:
                    if file.endswith(".json") and "sbom" in file.lower():
                        sbom_files.append(os.path.join(root, file))
    return sbom_files

async def init_vex_tix(
    owner: str,
    sbom_files: list[str],
    paths: list[str]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    timestamp = str(datetime.now())
    result = []
    for sbom_file in sbom_files:
        with open(sbom_file, encoding="utf-8") as sbom_file_handle:
            sbom_json = load(sbom_file_handle)
            if "components" in sbom_json and isinstance(sbom_json["components"], list):
                tix = await load_json_template("app/templates/file/tix_template.json")
                tix["author"] = owner
                tix["timestamp"] = timestamp
                tix["last_updated"] = timestamp
                vex = await load_json_template("app/templates/file/vex_template.json")
                vex["author"] = owner
                vex["timestamp"] = timestamp
                vex["last_updated"] = timestamp
                vex, tix = await generate_statements(sbom_json["components"], paths, timestamp, vex, tix)
                result.append((vex, tix))
    if not result:
        raise InvalidSbomException()
    return result


async def get_files_path(directory_path: str) -> list[str]:
    files = []
    for branch in ("/main", "/master"):
        paths = glob(directory_path + branch + "/**", recursive=True)
        for _path in paths:
            if not isdir(_path):
                files.append(_path)
    return files


async def generate_statements(
    components: list[dict[str, Any]],
    paths: list[str],
    timestamp: str,
    vex: dict[str, Any],
    tix: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    for component in components:
        if "name" in component:
            if "purl" in component and "version" in component:
                package_manager = component["purl"].split(":")[1].split("/")[0]
                if package_manager in ("pypi", "npm", "maven", "cargo", "nuget"):
                    node_type = get_node_type(package_manager)
                    component_name, import_name = await init_package_by_manager(component, node_type)
                    vulnerabilities_ids = await read_vulnerability_ids_by_version_and_package(
                        node_type.value, component_name, component["version"]
                    )
                    for vulnerability_id in vulnerabilities_ids:
                        priority, status, justification, tix_statement = await generate_tix_statement(vulnerability_id, paths, import_name, component_name, component["version"], timestamp, package_manager)
                        tix["statements"].append(tix_statement)
                        vex["statements"].append(
                            await generate_vex_statement(vulnerability_id, timestamp, package_manager, priority, status, justification)
                        )
    vex["statements"] = sorted(vex["statements"], key=lambda d: d['priority'], reverse=True)
    return vex, tix


async def init_package_by_manager(component: dict[str, Any], node_type: NodeType) -> str:
    if "group" in component:
        separator = ":" if node_type.value == "MavenPackage" else "/"
        component["name"] = f"{component["group"]}{separator}{component["name"]}"
    elif node_type.value == "MavenPackage":
        if ":" not in component["name"]:
            raise InvalidMavenComponentException()
    component_name, import_name = await init_package(InitPackageRequest(name=component["name"], node_type=node_type))
    return component_name, import_name


async def generate_vex_statement(vulnerability_id: str, timestamp: str, manager: str, priority: float, status: str, justification: str) -> dict[str, Any]:
    statement = await load_json_template("app/templates/statement/vex_statement_template.json")
    vulnerability = await read_vulnerability_by_id(vulnerability_id)
    statement["vulnerability"]["@id"] = f"https://nvd.nist.gov/vuln/detail/{vulnerability["id"]}"
    statement["vulnerability"]["name"] = vulnerability["id"]
    statement["vulnerability"]["description"] = vulnerability["details"]
    statement["timestamp"] = timestamp
    statement["last_updated"] = timestamp
    statement["supplier"] = manager
    if status:
        statement["status"] = status
    if justification:
        statement["justification"] = justification
    statement["priority"] = priority
    return statement


async def generate_tix_statement(vulnerability_id: str, paths: list[str], import_name: str, name: str, version: str, timestamp:str, manager: str) -> tuple[float, str, str, dict[str, Any]]:
    vulnerability = await read_vulnerability_by_id(vulnerability_id)
    tix_statement = await load_json_template("app/templates/statement/tix_statement_template.json")
    tix_statement["purl"] = f"pkg:{manager}/{name}@{version}"
    tix_statement["timestamp"] = timestamp
    tix_statement["last_updated"] = timestamp
    tix_statement["vulnerability"]["@id"] = f"https://nvd.nist.gov/vuln/detail/{vulnerability["id"]}"
    tix_statement["vulnerability"]["name"] = vulnerability["id"]
    tix_statement["vulnerability"]["description"] = vulnerability["details"]
    tix_statement["vulnerability"]["cvss"]["vuln_impact"] = vulnerability["vuln_impact"]
    tix_statement["vulnerability"]["cvss"]["attack_vector"] = vulnerability["attack_vector"]
    for cwe in vulnerability["cwes"]:
        _cwe = {}
        _cwe["@id"] = f"https://cwe.mitre.org/data/definitions/{cwe["@ID"]}.html"
        _cwe["abstraction"] = cwe["@Abstraction"]
        _cwe["name"] = cwe["@ID"]
        _cwe["description"] = cwe["Extended_Description"] if "Extended_Description" in cwe else cwe["Description"]
        if "Background_Details" in cwe:
            _cwe["background_detail"] = cwe["Background_Details"]["Background_Detail"]
        if "Common_Consequences" in cwe:
            _cwe["consequences"] = cwe["Common_Consequences"]["Consequence"]
        if "Detection_Methods" in cwe:
            _cwe["detection_methods"] = cwe["Detection_Methods"]["Detection_Method"]
        if "Potential_Mitigations" in cwe:
            _cwe["potential_mitigations"] = cwe["Potential_Mitigations"]["Mitigation"]
        if "Demonstrative_Examples" in cwe:
            _cwe["demonstrative_examples"] = cwe["Demonstrative_Examples"]["Demonstrative_Example"]
        tix_statement["vulnerability"]["cwes"].append(_cwe)
    is_imported_any = False
    for path in paths:
        if await is_imported(path, import_name, name, manager):
            is_imported_any = True
            reacheable_code = {}
            reacheable_code["path_to_file"] = path.replace("repositories/", "")
            affected_artefacts = {}
            if "affected_artefacts" in vulnerability:
                affected_artefacts = vulnerability["affected_artefacts"]
            reacheable_code["used_artifacts"] = await get_used_artifacts(path, import_name, name, vulnerability["details"], affected_artefacts, manager)
            if reacheable_code["used_artifacts"]:
                tix_statement["reachable_code"].append(reacheable_code)
    for exploit in vulnerability["exploits"]:
        _exploit = {}
        _exploit["@id"] = exploit["href"] if exploit["href"] else "Unknown"
        _exploit["attack_vector"] = exploit["cvss"]["vector"] if "cvss" in exploit else "NONE"
        _exploit["description"] = "" if exploit["type"] == "githubexploit" else exploit["description"]
        _exploit["payload"] = ""
        if exploit["type"] == "githubexploit":
            _exploit["payload"] = exploit["description"]
        else:
            if "sourceData" in exploit:
                _exploit["payload"] = exploit["sourceData"]
        tix_statement["exploits"].append(_exploit)
    status = None
    justification = None
    if "affected_artefacts" in vulnerability:
        if not is_imported_any and vulnerability["affected_artefacts"]:
            status = "not_affected"
            justification = "component_not_present"
        elif vulnerability["affected_artefacts"] and not tix_statement["reachable_code"]:
            status = "not_affected"
            justification = "vulnerable_code_not_present"
    priority = vulnerability["vuln_impact"]*0.7
    if tix_statement["reachable_code"]:
        priority += 1
    if tix_statement["exploits"]:
        priority += 1
    if tix_statement["vulnerability"]["cwes"]:
        priority += 1
    return priority, status, justification, tix_statement
