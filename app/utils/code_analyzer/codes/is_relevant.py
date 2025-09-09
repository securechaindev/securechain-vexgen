async def is_relevant(artefact: str, artefacts: list[str], cve_description: str) -> bool:
    return (
        artefact in artefacts or
        artefact.lower() in cve_description.lower()
    )
