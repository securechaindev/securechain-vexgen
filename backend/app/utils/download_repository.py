from os import makedirs
from os.path import exists
from shutil import rmtree

from git import GitCommandError, Repo

pip_files = ["pyproject.toml", "setup.cfg", "setup.py", "requirements.txt"]
npm_files = ["package.json"]
mvn_files = ["pom.xml"]

async def download_repository(owner: str, name: str) -> str:
    carpeta_descarga = "repositories/" + name
    rmtree(carpeta_descarga, ignore_errors=True)
    makedirs(carpeta_descarga)
    for branch in ("main", "master"):
        branch_dir = carpeta_descarga + "/" + branch
        if not exists(branch_dir):
            makedirs(branch_dir)
        try:
            Repo.clone_from(
                f"https://github.com/{owner}/{name}.git", branch_dir, branch=branch
            )
        except GitCommandError:
            continue
    return carpeta_descarga
