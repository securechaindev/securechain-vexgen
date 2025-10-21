from os import makedirs
from os.path import exists
from pathlib import Path
from shutil import rmtree
from uuid import uuid4

from git import GitCommandError, Repo

from app.config import settings
from app.exceptions import CloneRepoException
from app.validators import GitValidator


class RepositoryDownloader:
    def __init__(self):
        self.base_directory = "repositories"
        self.git_config = settings.get_git_config()
        self.clone_options = settings.get_git_clone_options()

    async def download_repository(self, owner: str, name: str) -> str:
        unique_id = uuid4().hex[:8]
        directory = f"{self.base_directory}/{name}_{unique_id}"
        await self.prepare_directory(directory)
        url = f"https://github.com/{owner}/{name}.git"

        GitValidator.validate_git_url(url)

        try:
            repo = await self.clone_repository(url, directory)
            await self.configure_repository(repo, directory)
        except GitCommandError as err:
            raise CloneRepoException() from err

        return directory

    async def prepare_directory(self, directory: str) -> None:
        rmtree(directory, ignore_errors=True)
        if not exists(directory):
            makedirs(directory)

    async def clone_repository(self, url: str, directory: str) -> Repo:
        env = settings.get_os_environment()
        try:
            return Repo.clone_from(
                url,
                directory,
                env=env,
                multi_options=self.clone_options,
            )
        except GitCommandError as err:
            raise CloneRepoException() from err

    async def configure_repository(self, repo: Repo, directory: str) -> None:
        empty_hooks = Path(directory) / ".git" / "hooks-empty"
        empty_hooks.mkdir(parents=True, exist_ok=True)

        try:
            for key, value in self.git_config.items():
                if key == "core.hooksPath":
                    repo.git.config(key, str(empty_hooks))
                else:
                    repo.git.config(key, value)
        except GitCommandError as err:
            raise CloneRepoException() from err
