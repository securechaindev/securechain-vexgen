from typing import Any

import aiofiles
from regex import compile, escape, search

from .base_analyzer import BaseCodeAnalyzer
from .code_validator import CodeValidator


class PythonAnalyzer(BaseCodeAnalyzer):
    def __init__(self):
        super().__init__()
        self.assign_pattern = compile(r"(\w+)\s*=\s*(\w+)\(")

    def get_import_pattern(self, import_name: str) -> str:
        return rf"(from|import)\s+({escape(import_name)})\b"

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
        if stripped.startswith("#"):
            return True, inside_comment
        if "import" in stripped:
            return True, inside_comment
        return False, inside_comment

    async def extract_patterns(
        self,
        import_names: list[str],
        code: str
    ) -> tuple[list[tuple[str, str, str | None]], dict[tuple[str, str, str], list[str]]]:
        used_artefacts: dict[tuple[str, str, str], list[str]] = {}

        for line in code.splitlines():
            match = self.assign_pattern.search(line)
            if match:
                alias = match.group(1)
                self.known_aliases.add(alias)

        patterns = []
        for target in import_names:
            escaped = escape(target)
            patterns.extend([
                (rf"{escaped}\.[^\(\)\s:]+", "dot_access", target),
                (rf"from\s+{escaped}\.[^\s]+\s+import\s+[\w,\s]+", "from_submodule_import", target),
                (rf"from\s+{escaped}\s+import\s+[\w,\s]+", "from_module_import", target)
            ])

        patterns.append((r"(\w+)\.(\w+)\s*\(", "alias_method_call", None))

        return patterns, used_artefacts

    async def process_match(
        self,
        match: Any,
        split_type: str,
        affected_artefacts: dict[str, dict[str, dict[str, list[str]]]],
        cve_description: str,
        used_artefacts: dict[tuple[str, str, str], list[str]],
        new_artefacts: list[str]
    ) -> list[str] | None:
        if split_type in ("from_module_import", "from_submodule_import"):
            import_part = match.group(0).split("import")[1]
            artefacts = [a.strip() for a in import_part.split(",")]
        elif split_type == "dot_access":
            match_str = match.group(0)
            artefacts = [a.strip() for a in match_str.split(".")[1:]]
        elif split_type == "alias_method_call":
            alias, method = match.group(1), match.group(2)
            if alias in self.known_aliases:
                for source, data in affected_artefacts.items():
                    for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                        if await CodeValidator.is_relevant(method, artefacts_list, cve_description):
                            used_artefacts.setdefault((method, artefact_type, source), [])
                            new_artefacts.append(method)
            return None
        else:
            return None

        result = []
        for artefact in artefacts:
            clean_artefact = artefact.strip()
            if not clean_artefact or not CodeValidator.is_valid_artefact_name(clean_artefact):
                continue
            for source, data in affected_artefacts.items():
                for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                    if await CodeValidator.is_relevant(clean_artefact, artefacts_list, cve_description):
                        used_artefacts.setdefault((clean_artefact, artefact_type, source), [])
                        result.append(clean_artefact)
        return result
