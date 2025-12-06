from os import walk
from os.path import join
from pathlib import Path
from typing import Any

from app.domain import BaseCodeAnalyzer, CodeAnalyzerFactory
from app.domain.vex_generation.constants import SKIP_DIRECTORIES, TEXT_FILE_EXTENSIONS
from app.domain.vex_generation.helpers import PathHelper
from app.domain.vex_generation.parsers import NodeTypeMapper
from app.templates import create_tix_statement_template

from .statement_helpers import StatementHelpers


class TIXStatementGenerator:
    def __init__(self, directory: str):
        self.directory = directory
        self.skip_dirs = SKIP_DIRECTORIES
        self.text_extensions = TEXT_FILE_EXTENSIONS
        self.is_dependency_imported: bool = False

    async def generate_tix_statement(
        self,
        vulnerability: dict[str, Any],
        purl: str,
        timestamp: str,
        import_names: list[str],
        node_type: str,
    ) -> dict[str, Any]:
        tix_statement = create_tix_statement_template()

        await self.populate_vulnerability_info(tix_statement, vulnerability, purl, timestamp)

        await self.populate_reachable_code(
            tix_statement,
            vulnerability,
            import_names,
            node_type
        )

        await self.populate_exploits(tix_statement, vulnerability)

        return tix_statement

    async def populate_vulnerability_info(
        self,
        tix_statement: dict[str, Any],
        vulnerability: dict[str, Any],
        purl: str,
        timestamp: str
    ) -> None:
        tix_statement["vulnerability"]["@id"] = StatementHelpers.build_vulnerability_id(vulnerability.get("id", ""))
        tix_statement["vulnerability"]["name"] = vulnerability.get("id", "")
        tix_statement["vulnerability"]["description"] = vulnerability.get("details", "")
        tix_statement["vulnerability"]["cvss"]["vuln_impact"] = vulnerability.get("vuln_impact", "")
        tix_statement["vulnerability"]["cvss"]["attack_vector"] = vulnerability.get("attack_vector", "")
        tix_statement["products"][0]["identifiers"]["purl"] = purl
        StatementHelpers.set_timestamps(tix_statement, timestamp)

        for cwe in vulnerability.get("cwes", []):
            tix_statement["vulnerability"]["cwes"].append(
                StatementHelpers.build_cwe_dict(cwe)
            )

    async def populate_reachable_code(
        self,
        tix_statement: dict[str, Any],
        vulnerability: dict[str, Any],
        import_names: list[str],
        node_type: str
    ) -> None:
        for path in await self.get_files_path(node_type):
            analyzer = CodeAnalyzerFactory.get_analyzer(node_type)
            if not await analyzer.is_imported(path, import_names):
                continue

            self.is_dependency_imported = True

            reachable_code_entry = await self.build_reachable_code_entry(
                path,
                vulnerability,
                import_names,
                analyzer
            )

            if reachable_code_entry and reachable_code_entry.get("used_artefacts"):
                tix_statement["reachable_code"].append(reachable_code_entry)

    async def build_reachable_code_entry(
        self,
        path: str,
        vulnerability: dict[str, Any],
        import_names: list[str],
        analyzer: BaseCodeAnalyzer
    ) -> dict[str, Any]:
        relative_path = PathHelper.get_relative_path(path, self.directory)
        affected_artefacts = vulnerability.get("affected_artefacts", {})
        used_artefacts = await analyzer.get_used_artefacts(
            path,
            import_names,
            vulnerability.get("details", ""),
            affected_artefacts
        )

        return {
            "path_to_file": relative_path,
            "used_artefacts": used_artefacts
        }

    async def populate_exploits(
        self,
        tix_statement: dict[str, Any],
        vulnerability: dict[str, Any]
    ) -> None:
        for exploit in vulnerability.get("exploits", []):
            exploit_dict = StatementHelpers.build_exploit_dict(exploit)
            if exploit_dict["@id"] != "Unknown":
                tix_statement["exploits"].append(exploit_dict)

    async def get_files_path(self, node_type: str) -> list[str]:
        extension = NodeTypeMapper.get_extension(node_type)
        result: list[str] = []

        for root, dirs, files in walk(self.directory):
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]

            for file in files:
                if not file.endswith(extension):
                    continue

                file_path = join(root, file)
                p = Path(file_path)

                if p.suffix.lower() not in self.text_extensions:
                    continue

                result.append(file_path)

        return result
