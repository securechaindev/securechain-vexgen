from typing import Any

import aiofiles
from regex import compile, escape, search

from .base_analyzer import BaseCodeAnalyzer
from .code_validator import CodeValidator


class RustAnalyzer(BaseCodeAnalyzer):
    def __init__(self):
        super().__init__()
        self.alias_pattern = compile(r"let\s+(\w+)\s*=\s*([\w:]+)::new\s*\(")

    def get_import_pattern(self, import_name: str) -> str:
        return rf"extern crate\s+{import_name};|use\s+{import_name}::"

    async def is_imported(self, file_path: str, import_names: list[str]) -> bool:
        try:
            async with aiofiles.open(file_path, encoding="utf-8") as file:
                code = await file.read()
                for import_name in import_names:
                    pattern = self.get_import_pattern(import_name)
                    if search(pattern, code):
                        return True
        except Exception:
            return False

    def should_skip_line(self, line: str, inside_comment: bool) -> tuple[bool, bool]:
        stripped = line.strip()

        if inside_comment:
            if "*/" in stripped:
                return True, False
            return True, True

        if stripped.startswith("/*"):
            return True, True

        if stripped.startswith("//"):
            return True, False

        if search(r"extern crate\s|use\s", line):
            return True, False

        return False, False

    async def extract_patterns(
        self,
        import_names: list[str],
        code: str
    ) -> tuple[list[tuple[str, str, str | None]], dict[tuple[str, str, str], list[str]]]:
        used_artefacts: dict[tuple[str, str, str], list[str]] = {}

        for line in code.splitlines():
            match = self.alias_pattern.search(line)
            if match:
                alias = match.group(1)
                self.known_aliases.add(alias)

        patterns = []
        for target in import_names:
            escaped = escape(target)
            patterns.extend([
                (rf"{escaped}::[^\s\(\);]+", "split_by_double_colon", target),
                (rf"use\s+{escaped}::{{[^}}]+}};", "split_by_braces", target),
                (rf"let\s+{{[^}}]+}}\s*=\s*{escaped}::", "split_by_braces", target)
            ])

        patterns.append((r"(\w+)\.(\w+)\s*\(", "alias_method_call", None))

        return patterns, used_artefacts

    async def process_match(
        self,
        match: Any,
        split_type: str,
        affected_artefacts: dict[str, dict[str, Any]],
        cve_description: str,
        used_artefacts: dict[tuple[str, str, str], list[str]],
        new_artefacts: list[str]
    ) -> list[str] | None:

        if split_type == "split_by_double_colon":
            artefacts = match.group(0).split("::")[1:]
        elif split_type == "split_by_braces":
            content = match.group(0).split("{")[1].split("}")[0]
            artefacts = [a.strip() for a in content.split(",")]
        elif split_type == "alias_method_call":
            alias, method = match.group(1), match.group(2)
            if alias in self.known_aliases:
                for source, artefact_types in affected_artefacts.items():
                    for artefact_type, artefacts_list in artefact_types.get("artefacts", {}).items():
                        if await CodeValidator.is_relevant(method, artefacts_list, cve_description):
                            used_artefacts.setdefault((method, artefact_type, source), [])
                            new_artefacts.append(method)
            return None
        else:
            return None

        result = []
        for artefact in artefacts:
            clean = artefact.strip()
            if not clean or not CodeValidator.is_valid_artefact_name(clean):
                continue
            for source, artefact_types in affected_artefacts.items():
                for artefact_type, artefacts_list in artefact_types.get("artefacts", {}).items():
                    if await CodeValidator.is_relevant(clean, artefacts_list, cve_description):
                        used_artefacts.setdefault((clean, artefact_type, source), [])
                        result.append(clean)
        return result
