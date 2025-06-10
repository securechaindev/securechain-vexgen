from typing import Any

from regex import findall, search


async def cs_is_imported(file_path: str, namespace: str) -> Any:
    with open(file_path, encoding="utf-8") as file:
        try:
            code = file.read()
            return search(rf"using\s+{namespace};", code)
        except Exception:
            return False


async def cs_get_used_artifacts(
    filename: str,
    namespace: str,
    cve_description: str,
    affected_artefacts: dict[str, list[str]]
) -> list[dict[str, Any]]:
    with open(filename, encoding="utf-8") as file:
        code = file.read()
        current_line = 1
        used_artifacts = await get_child_artifacts(namespace, code, cve_description, affected_artefacts)
        for line in code.split("\n"):
            if not search(r"using\s", line):
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
    parent: str,
    code: str,
    cve_description: str,
    affected_artefacts: dict[str, list[str]]
) -> dict[tuple[str, str], list[int]]:
    used_artifacts: dict[tuple[str, str], list[int]] = {}
    def is_relevant(artifact: str, artifact_type: str) -> bool:
        artifact_lower = artifact.lower()
        if artifact_lower in cve_description.lower():
            return True
        return artifact in affected_artefacts.get(artifact_type, [])
    for match in findall(rf"{parent}\.[^\(\)\s:;]+", code):
        for artifact in match.split(".")[1:]:
            clean = artifact.strip()
            for artifact_type in affected_artefacts:
                if is_relevant(clean, artifact_type):
                    used_artifacts.setdefault((clean, artifact_type), [])
    for match in findall(rf"using\s+{parent}\s*;\s*{{[^}}]+}}", code):
        for artifact in match.split("{")[1].split("}")[0].split(","):
            clean = artifact.strip()
            for artifact_type in affected_artefacts:
                if is_relevant(clean, artifact_type):
                    used_artifacts.setdefault((clean, artifact_type), [])
    aux = {}
    for (artifact, _) in used_artifacts:
        aux.update(await get_child_artifacts(artifact, code, cve_description, affected_artefacts))
    used_artifacts.update(aux)
    return used_artifacts
