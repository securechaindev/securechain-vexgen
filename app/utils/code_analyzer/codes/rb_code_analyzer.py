from typing import Any

from regex import escape, findall, search

from .is_relevant import is_relevant


async def rb_is_imported(file_path: str, gem_name: str, name: str) -> Any:
    try:
        with open(file_path, encoding="utf-8") as file:
            code = file.read()
            pattern = rf"(require|require_relative|include|extend)\s+['\"]?({escape(name)}|{escape(gem_name)})['\"]?\b"
            return search(pattern, code)
    except Exception:
        return False


async def rb_get_used_artifacts(
    filename: str,
    gem_name: str,
    name: str,
    cve_description: str,
    affected_artefacts: dict[str, dict[str, list[str]]]
) -> list[dict[str, Any]]:
    with open(filename, encoding="utf-8") as file:
        code = file.read()
        current_line = 1
        used_artifacts = await get_child_artifacts(gem_name, name, code, cve_description, affected_artefacts, set())
        for line in code.split("\n"):
            if not search(r"require|require_relative|include|extend", line):
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
    gem_name: str,
    name: str,
    code: str,
    cve_description: str,
    affected_artefacts: dict[str, dict[str, list[str]]],
    visited: set[str]
) -> dict[tuple[str, str, str], list[str]]:
    used_artifacts: dict[tuple[str, str, str], list[str]] = {}
    patterns = []
    for target in [name, gem_name]:
        escaped = escape(target)
        patterns.extend([
            (rf"{escaped}::[^\(\)\s:;]+", "split_by_double_colon"),
            (rf"{escaped}\.[^\(\)\s:;]+", "split_by_dot"),
            (rf"require\s+['\"]({escaped}/[^'\"]+)['\"]", "split_by_slash"),
            (rf"require_relative\s+['\"]({escaped}/[^'\"]+)['\"]", "split_by_slash"),
            (rf"include\s+{escaped}::[^\(\)\s:;]+", "split_by_double_colon_include"),
            (rf"extend\s+{escaped}::[^\(\)\s:;]+", "split_by_double_colon_extend"),
        ])
    for pattern, split_type in patterns:
        for match in findall(pattern, code):
            if split_type == "split_by_double_colon":
                artifacts = match.split("::")[1:]
            elif split_type == "split_by_dot":
                artifacts = match.split(".")[1:]
            elif split_type == "split_by_slash":
                artifacts = [match.split("/")[-1]]
            elif split_type in ["split_by_double_colon_include", "split_by_double_colon_extend"]:
                artifacts = match.split("::")[1:]
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
                gem_name=artifact,
                name=artifact,
                code=code,
                cve_description=cve_description,
                affected_artefacts=affected_artefacts,
                visited=visited
            ))
    used_artifacts.update(aux)
    return used_artifacts
