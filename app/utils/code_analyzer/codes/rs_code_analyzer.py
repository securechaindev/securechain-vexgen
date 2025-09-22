from typing import Any

from regex import compile, escape, finditer, search

from .is_relevant import is_relevant
from .validation import is_valid_artefact_name


async def rs_is_imported(file_path: str, import_names: list[str]) -> bool:
    try:
        with open(file_path, encoding="utf-8") as file:
            code = file.read()
            for import_name in import_names:
                pattern = rf"extern crate\s+{import_name};|use\s+{import_name}::"
                if search(pattern, code):
                    return True
    except Exception:
        return False


async def rs_get_used_artefacts(
    filename: str,
    import_names: list[str],
    cve_description: str,
    affected_artefacts: dict[str, dict[str, list[str]]]
) -> list[dict[str, Any]]:
    with open(filename, encoding="utf-8") as file:
        code = file.read()
        current_line = 1
        found_artefacts = await get_child_artefacts(import_names, code, cve_description, affected_artefacts, set())
        used_artefacts: dict[tuple[str, str, str], list[str]] = {}
        for key in found_artefacts.keys():
            used_artefacts[key] = []
        inside_block_comment = False
        for line in code.split("\n"):
            stripped = line.strip()
            if inside_block_comment:
                if "*/" in stripped:
                    inside_block_comment = False
                current_line += 1
                continue
            if stripped.startswith("/*"):
                inside_block_comment = True
                current_line += 1
                continue
            if stripped.startswith("//"):
                current_line += 1
                continue
            if search(r"extern crate\s|use\s", line):
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
        result = []
        groups_by_name_type = {}
        for (artefact_name, artefact_type, source), used_in_lines in used_artefacts.items():
            line_numbers = ",".join(used_in_lines)
            groups_by_name_type.setdefault((artefact_name, artefact_type, line_numbers), []).append(source)
        for (artefact_name, artefact_type, used_in_lines), sources in groups_by_name_type.items():
            if (artefact_name and artefact_type and
                is_valid_artefact_name(artefact_name) and
                is_valid_artefact_name(artefact_type)):
                result.append({
                    "artefact_name": artefact_name.strip(),
                    "artefact_type": artefact_type.strip(),
                    "sources": [s.strip() for s in sources if s and s.strip()],
                    "used_in_lines": used_in_lines
                })
        return result


async def get_child_artefacts(
    import_names: list[str],
    code: str,
    cve_description: str,
    affected_artefacts: dict[str, dict[str, list[str]]],
    visited: set[str]
) -> dict[tuple[str, str, str], list[str]]:
    used_artefacts: dict[tuple[str, str, str], list[str]] = {}
    known_aliases: set[str] = set()
    lines = code.splitlines()
    alias_pattern = compile(r"let\s+(\w+)\s*=\s*([\w:]+)::new\s*\(")
    for line in lines:
        match = alias_pattern.search(line)
        if match:
            alias = match.group(1)
            known_aliases.add(alias)
    patterns = []
    for target in import_names:
        escaped = escape(target)
        patterns.extend([
            (rf"{escaped}::[^\s\(\);]+", "split_by_double_colon"),
            (rf"use\s+{escaped}::{{[^}}]+}};", "split_by_braces"),
            (rf"let\s+{{[^}}]+}}\s*=\s*{escaped}::", "split_by_braces")
        ])
    patterns.append((r"(\w+)\.(\w+)\s*\(", "alias_method_call"))
    new_artefacts = []
    for pattern, split_type in patterns:
        for match in finditer(pattern, code):
            if split_type == "split_by_double_colon":
                artefacts = match.group(0).split("::")[1:]
            elif split_type == "split_by_braces":
                content = match.group(0).split("{")[1].split("}")[0]
                artefacts = [a.strip() for a in content.split(",")]
            elif split_type == "alias_method_call":
                alias, method = match.group(1), match.group(2)
                if alias in known_aliases:
                    for source, artefact_types in affected_artefacts.items():
                        for artefact_type, artefacts_list in artefact_types.get("artefacts", {}).items():
                            if await is_relevant(method, artefacts_list, cve_description):
                                used_artefacts.setdefault((method, artefact_type, source), [])
                                new_artefacts.append(method)
                continue
            else:
                continue
            for artefact in artefacts:
                clean = artefact.strip()
                if not clean or not is_valid_artefact_name(clean):
                    continue
                for source, artefact_types in affected_artefacts.items():
                    for artefact_type, artefacts_list in artefact_types.get("artefacts", {}).items():
                        if await is_relevant(clean, artefacts_list, cve_description):
                            used_artefacts.setdefault((clean, artefact_type, source), [])
                            new_artefacts.append(clean)
    for artefact in new_artefacts:
        if artefact not in visited:
            visited.add(artefact)
            aux = await get_child_artefacts(
                [artefact], code, cve_description, affected_artefacts, visited
            )
            used_artefacts.update(aux)
    return used_artefacts
