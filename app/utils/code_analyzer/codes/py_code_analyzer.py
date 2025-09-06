from typing import Any

from regex import escape, findall, search

from .is_relevant import is_relevant


async def py_is_imported(file_path: str, import_name: str, name: str) -> Any:
    try:
        with open(file_path, encoding="utf-8") as file:
            code = file.read()
            pattern = rf"(from|import)\s+({escape(name)}|{escape(import_name)})\b"
            return search(pattern, code)
    except Exception:
        return False


async def py_get_used_artifacts(
    filename: str,
    import_name: str,
    name: str,
    cve_description: str,
    affected_artefacts: dict[str, dict[str, list[str]]]
) -> list[dict[str, Any]]:
    with open(filename, encoding="utf-8") as file:
        code = file.read()
        current_line = 1
        used_artifacts = await get_child_artifacts(import_name, name, code, cve_description, affected_artefacts, set())
        for line in code.split("\n"):
            if "import" not in line:
                for (artifact, _type, source) in used_artifacts:
                    if artifact in line:
                        used_artifacts[(artifact, _type, source)].append(current_line)
            current_line += 1
        used_artifacts = {
            (artifact, _type, source): lines
            for (artifact, _type, source), lines in used_artifacts.items()
            if lines
        }
        result = []
        groups_by_name_type = {}
        for (artifact_name, artifact_type, source), used_in_lines in used_artifacts.items():
            groups_by_name_type.setdefault((artifact_name, artifact_type, used_in_lines), []).append(source)
        for (artifact_name, artifact_type, used_in_lines), sources in groups_by_name_type.items():
            result.append({
                "artifact_name": artifact_name,
                "artifact_type": artifact_type,
                "sources": sources,
                "used_in_lines": used_in_lines
            })
        return result


async def get_child_artifacts(
    import_name: str,
    name: str,
    code: str,
    cve_description: str,
    affected_artefacts: dict[str, list[str]],
    visited: set[str]
) -> dict[tuple[str, str, str], list[int]]:
    used_artifacts: dict[tuple[str, str, str], list[int]] = {}
    patterns = []
    for target in [name, import_name]:
        escaped = escape(target)
        patterns.extend([
            (rf"{escaped}\.[^\(\)\s:]+", None),
            (rf"from\s+{escaped}\.[^\(\)\s:]+\s+import\s+\w+(?:\s*,\s*\w+)*", None),
            (rf"from\s+{escaped}\s+import\s+\w+(?:\s*,\s*\w+)*", None),
        ])
    for pattern, _ in patterns:
        for match in findall(pattern, code):
            if "import" in match:
                artifacts = match.split("import")[1].split(",")
            else:
                artifacts = match.split(".")[1:]
            for artifact in artifacts:
                clean = artifact.strip()
                for source, artifact_types in affected_artefacts.items():
                    for artifact_type, artefacts in artifact_types["artefacts"].items():
                        if await is_relevant(clean, artefacts, cve_description):
                            used_artifacts.setdefault((clean, artifact_type, source), [])
    aux = {}
    for (artifact, _, _) in used_artifacts.keys():
        if artifact not in visited:
            visited.add(artifact)
            aux.update(await get_child_artifacts(
                import_name=artifact,
                name=artifact,
                code=code,
                cve_description=cve_description,
                affected_artefacts=affected_artefacts,
                visited=visited
            ))
    used_artifacts.update(aux)
    return used_artifacts
