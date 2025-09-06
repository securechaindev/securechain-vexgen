async def is_relevant(artifact: str, artefacts: list[str], cve_description: str) -> bool:
    artifact_lower = artifact.lower()
    if artifact_lower in cve_description.lower():
        return True
    return artifact in artefacts
