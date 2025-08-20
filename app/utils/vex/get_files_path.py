from glob import glob
from os.path import isfile
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "target", "build", "dist", "venv", ".tox",
    "__pycache__", ".mypy_cache", ".idea", ".vscode", "vendor"
}
TEXT_EXT = {
    ".py",".js",".ts",".jsx",".tsx",".java",".go",".rs",".php",".rb",
    ".cs",".cpp",".c",".m",".kt",".scala",".swift",".ps1", ".yml",
    ".yaml",".toml",".json",".ini",".cfg",".gradle",".pom",".xml"
}

async def get_files_path(directory: str) -> list[str]:
    paths = glob(directory + "/**", recursive=True)
    result: list[str] = []
    for _path in paths:
        if not isfile(_path):
            continue
        p = Path(_path)
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() not in TEXT_EXT:
            continue
        result.append(_path)
    return result
