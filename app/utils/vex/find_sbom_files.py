from os import walk
from os.path import exists, join


async def find_sbom_files(directory: str) -> list[str]:
    sbom_files = []
    if exists(directory):
        for root, _, files in walk(directory):
            for file in files:
                if file.endswith(".json") and "sbom" in file.lower():
                    sbom_files.append(join(root, file))
    return sbom_files
