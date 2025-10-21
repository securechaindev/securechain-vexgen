from abc import ABC, abstractmethod
from typing import Any

import aiofiles
from regex import Pattern, compile, finditer

from .code_validator import CodeValidator


class BaseCodeAnalyzer(ABC):
    def __init__(self):
        self.known_aliases: set[str] = set()

    @abstractmethod
    async def is_imported(self, file_path: str, import_names: list[str]) -> bool:
        pass

    @abstractmethod
    def get_import_pattern(self, import_name: str) -> str:
        pass

    @abstractmethod
    def should_skip_line(self, line: str, inside_comment: bool) -> tuple[bool, bool]:
        pass

    @abstractmethod
    async def extract_patterns(
        self,
        import_names: list[str],
        code: str
    ) -> tuple[list[tuple[str, str, str | None]], dict[tuple[str, str, str], list[str]]]:
        pass

    async def get_used_artefacts(
        self,
        filename: str,
        import_names: list[str],
        cve_description: str,
        affected_artefacts: dict[str, dict[str, list[str]]]
    ) -> list[dict[str, Any]]:
        async with aiofiles.open(filename, encoding="utf-8") as file:
            code = await file.read()

        found_artefacts = await self.get_child_artefacts(
            import_names, code, cve_description, affected_artefacts, set()
        )

        used_artefacts: dict[tuple[str, str, str], list[str]] = {
            key: [] for key in found_artefacts.keys()
        }

        current_line = 1
        inside_block_comment = False

        for line in code.split("\n"):
            should_skip, inside_block_comment = self.should_skip_line(line, inside_block_comment)
            if should_skip:
                current_line += 1
                continue

            for (artefact, _type, source) in found_artefacts.keys():
                if artefact in line:
                    used_artefacts[(artefact, _type, source)].append(str(current_line))
            current_line += 1

        used_artefacts = {
            key: lines
            for key, lines in used_artefacts.items()
            if lines
        }

        return self.build_result(used_artefacts)

    async def get_child_artefacts(
        self,
        import_names: list[str],
        code: str,
        cve_description: str,
        affected_artefacts: dict[str, dict[str, Any]],
        visited: set[str]
    ) -> dict[tuple[str, str, str], list[str]]:
        patterns, used_artefacts = await self.extract_patterns(
            import_names, code
        )

        new_artefacts = []
        for pattern_str, split_type, _target in patterns:
            pattern: Pattern = compile(pattern_str)
            for match in finditer(pattern, code):
                result = await self.process_match(
                    match, split_type, affected_artefacts, cve_description, used_artefacts, new_artefacts
                )
                if result:
                    new_artefacts.extend(result)

        for artefact in new_artefacts:
            if artefact not in visited:
                visited.add(artefact)
                child_result = await self.get_child_artefacts(
                    [artefact], code, cve_description, affected_artefacts, visited
                )
                used_artefacts.update(child_result)

        return used_artefacts

    @abstractmethod
    async def process_match(
        self,
        match: Any,
        split_type: str,
        affected_artefacts: dict[str, dict[str, Any]],
        cve_description: str,
        used_artefacts: dict[tuple[str, str, str], list[str]],
        new_artefacts: list[str]
    ) -> list[str] | None:
        pass

    def build_result(
        self,
        used_artefacts: dict[tuple[str, str, str], list[str]]
    ) -> list[dict[str, Any]]:
        result = []
        groups_by_name_type = {}

        for (artefact_name, artefact_type, source), used_in_lines in used_artefacts.items():
            line_numbers = ",".join(used_in_lines)
            groups_by_name_type.setdefault(
                (artefact_name, artefact_type, line_numbers), []
            ).append(source)

        for (artefact_name, artefact_type, used_in_lines), sources in groups_by_name_type.items():
            if (artefact_name and artefact_type and
                CodeValidator.is_valid_artefact_name(artefact_name) and
                CodeValidator.is_valid_artefact_name(artefact_type)):
                result.append({
                    "artefact_name": artefact_name.strip(),
                    "artefact_type": artefact_type.strip(),
                    "sources": [s.strip() for s in sources if s and s.strip()],
                    "used_in_lines": used_in_lines
                })

        return result
