from typing import Any

from regex import findall, search

from .is_relevant import is_relevant


async def js_ts_is_imported(file_path: str, dependency: str) -> Any:
    with open(file_path, encoding="utf-8") as file:
        try:
            code = file.read()
            return search(rf"(import\s+.*\s+from\s+['\"]{dependency}['\"]|require\(['\"]{dependency}['\"]\))", code)
        except Exception:
            return False


async def js_ts_get_used_artifacts(
    filename: str,
    dependency: str,
    cve_description: str,
    affected_artefacts: dict[str, dict[str, list[str]]]
) -> list[dict[str, Any]]:
    with open(filename, encoding="utf-8") as file:
        code = file.read()
        current_line = 1
        used_artifacts = await get_child_artifacts(dependency, code, cve_description, affected_artefacts)
        for line in code.split("\n"):
            if not search(r"import\s|require\(", line):
                for (artifact, _type, source) in used_artifacts:
                    if artifact in line:
                        used_artifacts[(artifact, _type, source)].append(str(current_line))
            current_line += 1
        used_artifacts = {
            (artifact, _type, source): lines
            for (artifact, _type, source), lines in used_artifacts.items()
            if lines
        }
        result = []
        groups_by_name_type = {}
        for (artifact_name, artifact_type, source), used_in_lines in used_artifacts.items():
            groups_by_name_type.setdefault((artifact_name, artifact_type, ",".join(used_in_lines)), []).append(source)
        for (artifact_name, artifact_type, used_in_lines), sources in groups_by_name_type.items():
            result.append({
                "artifact_name": artifact_name,
                "artifact_type": artifact_type,
                "sources": sources,
                "used_in_lines": used_in_lines
            })
        return result


async def get_child_artifacts(
    parent: str,
    code: str,
    cve_description: str,
    affected_artefacts: dict[str, list[str]]
) -> dict[tuple[str, str, str], list[str]]:
    used_artifacts: dict[tuple[str, str, str], list[str]] = {}
    patterns = [
        (rf"{parent}\.[^\(\)\s:;]+", "split_by_dot"),
        (rf"import\s+{{[^}}]+}}\s+from\s+['\"]{parent}['\"]", "split_by_braces"),
        (rf"const\s+{{[^}}]+}}\s*=\s*require\(['\"]{parent}['\"]\)", "split_by_braces"),
    ]
    for pattern, split_type in patterns:
        for match in findall(pattern, code):
            if split_type == "split_by_dot":
                artifacts = match.split(".")[1:]
            elif split_type == "split_by_braces":
                artifacts = match.split("{")[1].split("}")[0].split(",")
            for artifact in artifacts:
                clean = artifact.strip()
                for source, artifact_types in affected_artefacts.items():
                    for artifact_type, artefacts in artifact_types["artefacts"].items():
                        if await is_relevant(clean, artefacts, cve_description):
                            used_artifacts.setdefault((clean, artifact_type, source), [])
    aux = {}
    for (artifact, _, _) in used_artifacts:
        aux.update(await get_child_artifacts(artifact, code, cve_description, affected_artefacts))
    used_artifacts.update(aux)
    return used_artifacts
