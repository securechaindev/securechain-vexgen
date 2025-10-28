from datetime import datetime
from os import walk
from os.path import exists, join
from typing import Any

from pytz import UTC

from app.apis import GitHubService
from app.domain.vex_generation.helpers import PathHelper
from app.domain.vex_generation.infrastructure import RepositoryDownloader
from app.exceptions import SbomNotFoundException
from app.schemas import GenerateVEXTIXRequest, ProcessedSBOMResult, TIXCreate, VEXCreate
from app.services import TIXService, VEXService
from app.validators import PathValidator

from .vex_tix_initializer import VEXTIXInitializer


class SBOMProcessor:
    def __init__(
        self,
        generate_vex_tix_request: GenerateVEXTIXRequest,
        github_service: GitHubService,
        vex_service: VEXService,
        tix_service: TIXService
    ):
        self.request = generate_vex_tix_request
        self.github_service = github_service
        self.vex_service = vex_service
        self.tix_service = tix_service
        self.sbom_file_extension = ".json"
        self.sbom_identifier = "sbom"

    async def process_sboms(self) -> ProcessedSBOMResult:
        directory = await RepositoryDownloader().download_repository(
            self.request.owner, self.request.name
        )
        sbom_files = await self.find_sbom_files(directory)

        if not sbom_files:
            raise SbomNotFoundException()

        last_commit_date = await self.github_service.get_last_commit_date(
            self.request.owner, self.request.name
        )

        vex_list, tix_list, cached_paths = await self.check_cached_vex_tix(
            sbom_files, directory, last_commit_date
        )

        sboms_to_process = [
            sbom for sbom in sbom_files
            if PathHelper.get_relative_path(sbom, directory) not in cached_paths
        ]

        if sboms_to_process:
            new_vexs, new_tixs = await self.process_new_sboms(
                sboms_to_process, directory
            )
            vex_list.extend(new_vexs)
            tix_list.extend(new_tixs)

        all_sbom_paths = [PathHelper.get_relative_path(sbom, directory) for sbom in sbom_files]

        return ProcessedSBOMResult(
            vex_list=vex_list,
            tix_list=tix_list,
            sbom_paths=all_sbom_paths,
            directory=directory
        )

    async def check_cached_vex_tix(
        self,
        sbom_files: list[str],
        directory: str,
        last_commit_date: datetime
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
        vex_list = []
        tix_list = []
        cached_paths = []

        for sbom_file in sbom_files:
            sbom_path = PathHelper.get_relative_path(sbom_file, directory)

            last_vex = await self.vex_service.read_vex_by_owner_name_sbom_name(
                self.request.owner,
                self.request.name,
                sbom_path
            )

            if await self.is_cache_valid(last_vex, last_commit_date):
                last_tix = await self.tix_service.read_tix_by_owner_name_sbom_name(
                    self.request.owner,
                    self.request.name,
                    sbom_path
                )

                vex_list.append(last_vex["vex"])
                tix_list.append(last_tix["tix"])
                cached_paths.append(sbom_path)

                await self.vex_service.update_user_vexs(last_vex["_id"], self.request.user_id)

        return vex_list, tix_list, cached_paths

    async def is_cache_valid(self, last_vex: dict[str, Any] | None, last_commit_date: datetime) -> bool:
        if not last_vex:
            return False

        cache_date = last_vex["moment"].replace(tzinfo=UTC)
        commit_date = last_commit_date.replace(tzinfo=UTC)

        return cache_date >= commit_date

    async def process_new_sboms(
        self,
        sboms_to_process: list[str],
        directory: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        vex_tix_initializer = VEXTIXInitializer(directory)
        results = await vex_tix_initializer.init_vex_tix(self.request.owner, sboms_to_process)

        vex_list = []
        tix_list = []

        for sbom_file, (vex, tix) in zip(sboms_to_process, results, strict=True):
            sbom_path = PathHelper.get_relative_path(sbom_file, directory)
            await self.save_vex_tix(vex, tix, sbom_path)
            vex_list.append(vex)
            tix_list.append(tix)

        return vex_list, tix_list

    async def save_vex_tix(
        self,
        vex: dict[str, Any],
        tix: dict[str, Any],
        sbom_path: str
    ) -> None:
        now = datetime.now(UTC)

        vex_create = VEXCreate(
            owner=self.request.owner,
            name=self.request.name,
            sbom_path=sbom_path,
            sbom_name=sbom_path.split("/")[-1] if "/" in sbom_path else sbom_path,
            moment=now,
            statements=vex.get("statements", []),
            metadata=vex
        )
        vex_id = await self.vex_service.create_vex(vex_create)

        tix_create = TIXCreate(
            owner=self.request.owner,
            name=self.request.name,
            sbom_path=sbom_path,
            sbom_name=sbom_path.split("/")[-1] if "/" in sbom_path else sbom_path,
            moment=now,
            statements=tix.get("statements", []),
            metadata=tix
        )
        tix_id = await self.tix_service.create_tix(tix_create)

        await self.vex_service.update_user_vexs(vex_id, self.request.user_id)
        await self.tix_service.update_user_tixs(tix_id, self.request.user_id)

    async def find_sbom_files(self, directory: str) -> list[str]:
        sbom_files = []

        if not exists(directory):
            return sbom_files

        for root, _, files in walk(directory):
            for file in files:
                if file.endswith(self.sbom_file_extension) and self.sbom_identifier in file.lower():
                    file_path = join(root, file)
                    if PathValidator.validate_sbom_file(file_path):
                        sbom_files.append(file_path)

        return sbom_files
