from datetime import datetime
from json import loads
from typing import Any

from aiofiles import open as aio_open
from pytz import UTC

from app.domain.vex_generation.generators import StatementHelpers
from app.logger import logger
from app.templates import create_tix_template, create_vex_template

from .statement_generator import StatementsGenerator


class VEXTIXInitializer:
    def __init__(self, directory: str):
        self.directory = directory
        self.sbom_components_key = "components"

    async def init_vex_tix(
        self,
        owner: str,
        sbom_files: list[str],
    ) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
        timestamp = datetime.now(UTC).isoformat()
        results = []

        for sbom_file in sbom_files:
            try:
                vex_tix = await self.process_single_sbom(sbom_file, owner, timestamp)
                results.append((sbom_file, vex_tix[0], vex_tix[1]))
            except ValueError as e:
                logger.warning(f"Skipping invalid SBOM file {sbom_file}: {e}")
                continue

        return results

    async def process_single_sbom(
        self,
        sbom_file: str,
        owner: str,
        timestamp: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        sbom_json = await self.load_sbom_file(sbom_file)

        if not self.validate_sbom_structure(sbom_json):
            raise ValueError(f"Invalid SBOM structure in file: {sbom_file}")

        vex = create_vex_template()
        tix = create_tix_template()

        vex["author"] = owner
        tix["author"] = owner
        StatementHelpers.set_timestamps(vex, timestamp)
        StatementHelpers.set_timestamps(tix, timestamp)

        statements_generator = StatementsGenerator(self.directory)
        vex, tix = await statements_generator.generate_statements(
            sbom_json[self.sbom_components_key],
            timestamp,
            vex,
            tix
        )

        return vex, tix

    async def load_sbom_file(self, sbom_file: str) -> dict[str, Any]:
        async with aio_open(sbom_file, encoding="utf-8") as f:
            content = await f.read()
            return loads(content)

    def validate_sbom_structure(self, sbom_json: Any) -> bool:
        if not isinstance(sbom_json, dict):
            return False

        if self.sbom_components_key not in sbom_json:
            return False

        components = sbom_json[self.sbom_components_key]
        if not isinstance(components, list):
            return False

        return True
