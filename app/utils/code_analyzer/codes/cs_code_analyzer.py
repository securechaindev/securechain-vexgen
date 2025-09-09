from typing import Any

from regex import compile, escape, finditer, search

from .is_relevant import is_relevant


async def cs_is_imported(file_path: str, import_names: list [str]) -> bool:
    try:
        with open(file_path, encoding="utf-8") as file:
            code = file.read()
            for import_name in import_names:
                pattern = rf"using\s+{import_name};"
                if search(pattern, code):
                    return True
    except Exception:
        return False


async def cs_get_used_artefacts(
    filename: str,
    import_names: list[str],
    cve_description: str,
    affected_artefacts: dict[str, dict[str, list[str]]]
) -> list[dict[str, Any]]:
    with open(filename, encoding="utf-8") as file:
        code = file.read()
        current_line = 1
        used_artefacts = await get_child_artefacts(import_names, code, cve_description, affected_artefacts, set())
        for line in code.split("\n"):
            if not search(r"using\s", line):
                for (artefact, _type, source) in used_artefacts:
                    if artefact in line:
                        used_artefacts[(artefact, _type, source)].append(str(current_line))
            current_line += 1
        used_artefacts = {
            (artefact, _type, source): lines
            for (artefact, _type, source), lines in used_artefacts.items()
            if lines
        }
        result = []
        groups_by_name_type = {}
        for (artefact_name, artefact_type, source), used_in_lines in used_artefacts.items():
            groups_by_name_type.setdefault((artefact_name, artefact_type, ",".join(used_in_lines)), []).append(source)
        for (artefact_name, artefact_type, used_in_lines), sources in groups_by_name_type.items():
            result.append({
                "artefact_name": artefact_name,
                "artefact_type": artefact_type,
                "sources": sources,
                "used_in_lines": used_in_lines
            })
        return result


async def get_child_artefacts(
    import_names: list[str],
    code: str,
    cve_description: str,
    affected_artefacts: dict[str, dict[str, Any]],
    visited: set[str]
) -> dict[tuple[str, str, str], list[str]]:
    used_artefacts: dict[tuple[str, str, str], list[str]] = {}
    known_aliases: set[str] = set()
    using_namespaces: set[str] = set()
    lines = code.splitlines()
    assignment_pattern = compile(r"(?:var|[\w<>]+)\s+(\w+)\s*=\s*new\s+(\w+)\s*\(")
    for line in lines:
        match = assignment_pattern.search(line)
        if match:
            alias = match.group(1)
            known_aliases.add(alias)
    patterns = []
    for target in import_names:
        escaped = escape(target)
        patterns.extend([
            (rf"{escaped}\.[^\(\)\s:;]+", "dot_access"),
            (rf"using\s+{escaped}\s*;", "using_import"),
        ])
    patterns.append((r"(\w+)\.(\w+)\s*\(", "alias_method_call"))
    new_artefacts = []
    for pattern, split_type in patterns:
        for match in finditer(pattern, code):
            if split_type == "using_import":
                namespace = match.group(0).split("using")[1].strip().rstrip(";")
                using_namespaces.add(namespace)
                continue
            elif split_type == "dot_access":
                match_str = match.group(0)
                artefacts = match_str.split(".")[1:]
                for artefact in artefacts:
                    clean = artefact.strip()
                    for source, data in affected_artefacts.items():
                        for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                            if await is_relevant(clean, artefacts_list, cve_description):
                                used_artefacts.setdefault((clean, artefact_type, source), [])
                                new_artefacts.append(clean)
            elif split_type == "alias_method_call":
                alias, method = match.group(1), match.group(2)
                if alias in known_aliases:
                    for source, data in affected_artefacts.items():
                        for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                            if await is_relevant(method, artefacts_list, cve_description):
                                used_artefacts.setdefault((method, artefact_type, source), [])
                                new_artefacts.append(method)
    for namespace in using_namespaces:
        for source, data in affected_artefacts.items():
            if namespace not in source:
                continue
            for artefact_type, artefacts_list in data.get("artefacts", {}).items():
                for artefact in artefacts_list:
                    pattern = rf"\b{escape(artefact)}\b"
                    if search(pattern, code):
                        if await is_relevant(artefact, artefacts_list, cve_description):
                            used_artefacts.setdefault((artefact, artefact_type, source), [])
                            new_artefacts.append(artefact)
    for artefact in new_artefacts:
        if artefact not in visited:
            visited.add(artefact)
            child_result = await get_child_artefacts(
                [artefact], code, cve_description, affected_artefacts, visited
            )
            used_artefacts.update(child_result)
    return used_artefacts
