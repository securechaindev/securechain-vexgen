from os import environ, makedirs
from os.path import exists
from pathlib import Path
from shutil import rmtree

from git import GitCommandError, Repo

from app.exceptions import CloneRepoException


async def download_repository(owner: str, name: str) -> str:
    directory = "repositories/" + name
    rmtree(directory, ignore_errors=True)
    makedirs(directory)
    if not exists(directory):
        makedirs(directory)
    url = f"https://github.com/{owner}/{name}.git"
    env = dict(environ)
    try:
        repo = Repo.clone_from(
            url,
            directory,
            env=env,
            multi_options=[
                "--depth=1",
                "--single-branch",
                "--no-tags",
                "--filter=blob:none",
            ],
        )
    except GitCommandError as err:
        raise CloneRepoException() from err
    empty_hooks = Path(directory) / ".git" / "hooks-empty"
    empty_hooks.mkdir(parents=True, exist_ok=True)
    try:
        repo.git.config("core.hooksPath", str(empty_hooks))
        repo.git.config("submodule.recurse", "false")
        repo.git.config("fetch.fsckObjects", "true")
        repo.git.config("transfer.fsckObjects", "true")
        repo.git.config("core.autocrlf", "false")
        repo.git.config("core.safecrlf", "true")
    except GitCommandError as err:
        raise CloneRepoException() from err
    return directory
