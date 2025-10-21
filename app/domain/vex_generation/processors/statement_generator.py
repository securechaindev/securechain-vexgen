from typing import Any

from app.database import get_database_manager
from app.domain.vex_generation.generators import (
    TIXStatementGenerator,
    VEXStatementGenerator,
)
from app.domain.vex_generation.parsers import NodeTypeMapper, PURLParser
from app.exceptions import ComponentNotSupportedException
from app.services import PackageService, VersionService, VulnerabilityService


class StatementsGenerator:
    def __init__(
        self,
        directory: str,
        package_service: PackageService | None = None,
        version_service: VersionService | None = None,
        vulnerability_service: VulnerabilityService | None = None
    ):
        self.directory = directory

        # Get database manager instance
        db = get_database_manager()

        # Initialize services with database manager
        self.package_service = package_service or PackageService(db)
        self.version_service = version_service or VersionService(db)
        self.vulnerability_service = vulnerability_service or VulnerabilityService(db)

        self.vex_statement_generator = VEXStatementGenerator()
        self.tix_statement_generator = TIXStatementGenerator(directory)
        self.purl_parser = PURLParser()
        self.component_name_key = "name"
        self.component_purl_key = "purl"
        self.component_version_key = "version"

    async def generate_statements(
        self,
        components: list[dict[str, Any]],
        timestamp: str,
        vex: dict[str, Any],
        tix: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for component in components:
            if not await self.is_valid_component(component):
                continue

            await self.process_component(component, timestamp, vex, tix)

        vex["statements"] = sorted(vex["statements"], key=lambda d: d.get('priority', 0), reverse=True)
        return vex, tix

    async def is_valid_component(self, component: dict[str, Any]) -> bool:
        if self.component_name_key not in component:
            return False

        if not isinstance(component.get(self.component_name_key), str):
            return False

        if self.component_purl_key not in component or self.component_version_key not in component:
            return False

        purl = component.get(self.component_purl_key, "")
        if not await self.purl_parser.is_valid(purl):
            return False

        return True

    async def process_component(
        self,
        component: dict[str, Any],
        timestamp: str,
        vex: dict[str, Any],
        tix: dict[str, Any]
    ) -> None:
        purl = component[self.component_purl_key]
        purl_type = await self.purl_parser.extract_type(purl)

        if not purl_type:
            return

        try:
            node_type = self.map_node_type(purl_type)
        except ComponentNotSupportedException:
            return

        package_name, import_names = await self.package_service.read_package_by_name(
            node_type,
            component[self.component_name_key].lower()
        )

        vulnerability_ids = await self.version_service.read_vulnerability_ids_by_version_and_package(
            node_type,
            package_name,
            component[self.component_version_key]
        )

        for vulnerability_id in vulnerability_ids:
            await self.process_vulnerability(
                vulnerability_id,
                purl,
                timestamp,
                import_names,
                node_type,
                vex,
                tix
            )

    async def process_vulnerability(
        self,
        vulnerability_id: str,
        purl: str,
        timestamp: str,
        import_names: list[str],
        node_type: str,
        vex: dict[str, Any],
        tix: dict[str, Any]
    ) -> None:
        vulnerability = await self.vulnerability_service.read_vulnerability_by_id(vulnerability_id)

        tix_statement = await self.tix_statement_generator.generate_tix_statement(
            vulnerability,
            purl,
            timestamp,
            import_names,
            node_type
        )
        tix["statements"].append(tix_statement)

        vex_statement = await self.vex_statement_generator.generate_vex_statement(
            vulnerability,
            purl,
            node_type,
            timestamp,
            tix_statement
        )
        vex["statements"].append(vex_statement)

    def map_node_type(self, purl_type: str) -> str:
        return NodeTypeMapper.purl_type_to_node_type(purl_type)
