from typing import Any

import aiofiles
from regex import compile, escape, search

from .base_analyzer import BaseCodeAnalyzer
from .code_validator import CodeValidator


class CSharpAnalyzer(BaseCodeAnalyzer):
    def __init__(self):
        super().__init__()
        self.assignment_pattern = compile(r"(?:var|[\w<>]+)\s+(\w+)\s*=\s*new\s+(\w+)\s*\(")
        self.using_namespaces: set[str] = set()

    def get_import_pattern(self, import_name: str) -> str:
        return rf"using\s+{import_name};"

    async def is_imported(self, file_path: str, import_names: list[str]) -> bool:
        try:
            async with aiofiles.open(file_path, encoding="utf-8") as file:
                code = await file.read()
                for import_name in import_names:
                    pattern = self.get_import_pattern(import_name)
                    if search(pattern, code):
                        return True
                return False
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

        if search(r"using\s", line):
            return True, False

        return False, False

    async def extract_patterns(
        self,
        import_names: list[str],
        code: str
    ) -> tuple[list[tuple[str, str, str | None]], dict[tuple[str, str, str], list[str]]]:
        used_artefacts: dict[tuple[str, str, str], list[str]] = {}

        for line in code.splitlines():
            match = self.assignment_pattern.search(line)
            if match:
                alias = match.group(1)
                self.known_aliases.add(alias)

        patterns = []
        for target in import_names:
            escaped = escape(target)
            patterns.extend([
                (rf"{escaped}\.[^\(\)\s:;]+", "dot_access", target),
                (rf"using\s+{escaped}\s*;", "using_import", target)
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

        if split_type == "using_import":
            namespace = match.group(0).split("using")[1].strip().rstrip(";")
            self.using_namespaces.add(namespace)
            return None
        elif split_type == "dot_access":
            match_str = match.group(0)
            artefacts = match_str.split(".")[1:]
            result = []
            for artefact in artefacts:
                clean = artefact.strip()
                if not clean:
                    continue
                for source, data in affected_artefacts.items():
                    for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                        if await CodeValidator.is_relevant(clean, artefacts_list, cve_description):
                            used_artefacts.setdefault((clean, artefact_type, source), [])
                            result.append(clean)
            return result
        elif split_type == "alias_method_call":
            alias, method = match.group(1), match.group(2)
            if alias in self.known_aliases:
                for source, data in affected_artefacts.items():
                    for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                        if await CodeValidator.is_relevant(method, artefacts_list, cve_description):
                            used_artefacts.setdefault((method, artefact_type, source), [])
                            new_artefacts.append(method)
        return None

    async def get_used_artefacts(
        self,
        filename: str,
        import_names: list[str],
        cve_description: str,
        affected_artefacts: dict[str, dict[str, dict[str, list[str]]]]
    ) -> list[dict[str, Any]]:
        result = await super().get_used_artefacts(
            filename, import_names, cve_description, affected_artefacts
        )

        async with aiofiles.open(filename, encoding="utf-8") as file:
            code = await file.read()

        for namespace in self.using_namespaces:
            for source, data in affected_artefacts.items():
                if namespace not in source:
                    continue
                for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                    for artefact in artefacts_list:
                        if not artefact or not artefact.strip():
                            continue
                        pattern = rf"\b{escape(artefact)}\b"
                        if search(pattern, code):
                            if await CodeValidator.is_relevant(artefact, artefacts_list, cve_description):
                                artefact_name = artefact.strip()
                                if (artefact_name and artefact_type and
                                    CodeValidator.is_valid_artefact_name(artefact_name) and
                                    CodeValidator.is_valid_artefact_name(artefact_type)):
                                    result.append({
                                        "artefact_name": artefact_name,
                                        "artefact_type": artefact_type,
                                        "sources": [source.strip()],
                                        "used_in_lines": ""
                                    })

        return result
