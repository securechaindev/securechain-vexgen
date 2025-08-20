from typing import Any

from regex import escape, findall, search


async def python_is_imported(file_path: str, import_name: str, name: str) -> Any:
    try:
        with open(file_path, encoding="utf-8") as file:
            code = file.read()
            pattern = rf"(from|import)\s+({escape(name)}|{escape(import_name)})\b"
            return search(pattern, code)
    except Exception:
        return False


async def python_get_used_artifacts(
    filename: str,
    import_name: str,
    name: str,
    cve_description: str,
    affected_artefacts: dict[str, list[str]]
) -> list[dict[str, Any]]:
    with open(filename, encoding="utf-8") as file:
        code = file.read()
        current_line = 1
        used_artifacts = await get_child_artifacts(import_name, name, code, cve_description, affected_artefacts, set())
        for line in code.split("\n"):
            if "import" not in line:
                for (artifact, _type) in used_artifacts:
                    if artifact in line:
                        used_artifacts[(artifact, _type)].append(current_line)
            current_line += 1
        used_artifacts = {
            (artifact, _type): lines
            for (artifact, _type), lines in used_artifacts.items()
            if lines
        }
        result = []
        for (artifact_name, artifact_type), used_in_lines in used_artifacts.items():
            result.append({
                "artifact_name": artifact_name,
                "artifact_type": artifact_type,
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
) -> dict[tuple[str, str], list[int]]:
    used_artifacts: dict[tuple[str, str], list[int]] = {}
    def is_relevant(artifact: str, artifact_type: str) -> bool:
        return artifact in affected_artefacts.get(artifact_type, [])
    search_targets = [name, import_name]
    patterns = []
    for target in search_targets:
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
                for artifact_type in affected_artefacts.keys():
                    if is_relevant(clean, artifact_type):
                        used_artifacts.setdefault((clean, artifact_type), [])
    aux = {}
    for (artifact, _) in used_artifacts.keys():
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
